"""Generated ownership policies: naming, clause placement and rendering."""
from __future__ import annotations

import re

import pytest
from sqlalchemy import Boolean, Column, Integer, String, literal_column
from sqlalchemy.orm import declarative_base

from pgalchemy import PolicyCommands, PolicyType
from pgalchemy.config import config_value
from pgalchemy.permission_patterns import (
    default_policy_name_format,
    policy_require_match,
)
from pgalchemy.registry import registry

CALLER = "config_value"


@pytest.fixture()
def Model():
    Base = declarative_base()

    class Document(Base):
        __tablename__ = "documents"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)
        title = Column(String(50))

    return Document


@pytest.fixture()
def SchemaModel():
    Base = declarative_base()

    class Report(Base):
        __tablename__ = "reports"
        __table_args__ = {"schema": "app"}
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)

    return Report


def by_command(target) -> dict[PolicyCommands, object]:
    return {policy.for_: policy for policy in registry.get_policies(target)}


# -- default_policy_name_format ------------------------------------------------


def test_name_format_is_table_column_command(Model):
    name = default_policy_name_format(Model.__table__.c.owner_id, PolicyCommands.SELECT)

    assert name == "pol_documents_owner_id_select"


def test_name_format_lowercases_the_command(Model):
    """PostgreSQL folds unquoted identifiers, so the declared name must already
    match what ``pg_policies.policyname`` will report. The Alembic comparator
    looks policies up in that catalog by name."""
    for command in PolicyCommands:
        name = default_policy_name_format(Model.__table__.c.owner_id, command)
        assert name == name.lower()
        assert "PolicyCommands." not in name


def test_name_format_omits_the_schema(SchemaModel):
    """``str(Table)`` renders ``app.reports``; the dot would make the policy
    name parse as a schema qualification."""
    name = default_policy_name_format(SchemaModel.__table__.c.owner_id, PolicyCommands.SELECT)

    assert name == "pol_reports_owner_id_select"
    assert "." not in name


def test_generated_names_are_valid_unquoted_identifiers(Model, SchemaModel):
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    policy_require_match(SchemaModel.owner_id, config_value("app.user_id"))

    generated = list(registry.get_policies(Model)) + list(registry.get_policies(SchemaModel))
    assert len(generated) == 8
    for policy in generated:
        assert re.fullmatch(r"[a-z_][a-z0-9_]*", policy.name), policy.name


# -- which policies get declared -----------------------------------------------


def test_declares_one_policy_per_dml_command(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))

    assert set(by_command(Model)) == {
        PolicyCommands.SELECT,
        PolicyCommands.INSERT,
        PolicyCommands.UPDATE,
        PolicyCommands.DELETE,
    }


def test_policies_are_bound_to_the_columns_table(SchemaModel):
    policy_require_match(SchemaModel.owner_id, config_value("app.user_id"))

    for policy in registry.get_policies(SchemaModel):
        assert policy.table is SchemaModel.__table__
        assert policy.on_entity == "app.reports"


# -- clause placement per command ----------------------------------------------


def test_select_and_delete_use_using_only(Model):
    """``with check`` is not accepted for SELECT or DELETE."""
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    policies = by_command(Model)

    for command in (PolicyCommands.SELECT, PolicyCommands.DELETE):
        assert policies[command].using is not None
        assert policies[command].with_check is None


def test_insert_uses_with_check_only(Model):
    """``using`` is not accepted for INSERT -- there is no existing row to test."""
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    insert = by_command(Model)[PolicyCommands.INSERT]

    assert insert.using is None
    assert insert.with_check is not None


def test_update_uses_both_clauses(Model):
    """With only ``using``, a caller could update a row they own into one they
    do not; ``with check`` is what constrains the post-update row."""
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    update = by_command(Model)[PolicyCommands.UPDATE]

    assert update.using == update.with_check
    assert update.using is not None


# -- expression rendering ------------------------------------------------------


def test_match_renders_with_literal_binds(Model):
    """Regression: ``str(clause)`` leaves ``:current_setting_1`` placeholders,
    and Policy passes strings through verbatim, so they reach the migration."""
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert select_policy.using == (
        "public.documents.owner_id = current_setting('app.user_id', true)"
    )
    assert ":" not in select_policy.using


def test_every_generated_clause_is_free_of_placeholders(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))

    for policy in registry.get_policies(Model):
        for clause in (policy.using, policy.with_check):
            if clause is not None:
                assert ":" not in clause


def test_python_literals_are_inlined(Model):
    policy_require_match(Model.owner_id, 42)
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert select_policy.using == "public.documents.owner_id = 42"


def test_cast_getter_renders_the_cast(Model):
    """``current_setting`` returns text, so an integer column needs an explicit
    cast or PostgreSQL rejects the policy with ``operator does not exist:
    integer = text`` when the migration runs."""
    policy_require_match(Model.owner_id, config_value("app.user_id").cast(Integer))
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert select_policy.using == (
        "public.documents.owner_id = "
        "CAST(current_setting('app.user_id', true) AS INTEGER)"
    )


def test_override_is_or_ed_into_the_match(Model):
    policy_require_match(
        Model.owner_id,
        config_value("app.user_id"),
        override=config_value("app.is_admin").cast(Boolean),
    )
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert " OR " in select_policy.using
    assert "public.documents.owner_id = current_setting('app.user_id', true)" in select_policy.using
    assert "current_setting('app.is_admin', true)" in select_policy.using


def test_override_reaches_every_command(Model):
    policy_require_match(
        Model.owner_id,
        config_value("app.user_id"),
        override=literal_column("current_user = 'admin'"),
    )

    for policy in registry.get_policies(Model):
        clause = policy.using or policy.with_check
        assert "current_user = 'admin'" in clause


def test_no_override_leaves_a_bare_equality(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert " OR " not in select_policy.using


# -- options -------------------------------------------------------------------


def test_policy_type_defaults_to_permissive(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))

    for policy in registry.get_policies(Model):
        assert policy.as_ is PolicyType.PERMISSIVE
        assert "as PERMISSIVE" in policy.definition_sql()


def test_policy_type_propagates_to_every_policy(Model):
    policy_require_match(
        Model.owner_id, config_value("app.user_id"), policy_type=PolicyType.RESTRICTIVE
    )

    for policy in registry.get_policies(Model):
        assert policy.as_ is PolicyType.RESTRICTIVE
        assert "as RESTRICTIVE" in policy.definition_sql()


def test_custom_name_format_is_used_for_every_command(Model):
    def name_it(column, command):
        return f"own_{column.name}_{command}".lower()

    policy_require_match(Model.owner_id, config_value("app.user_id"), policy_name_format=name_it)

    assert {policy.name for policy in registry.get_policies(Model)} == {
        "own_owner_id_select",
        "own_owner_id_insert",
        "own_owner_id_update",
        "own_owner_id_delete",
    }


def test_custom_name_format_receives_the_column_and_command(Model):
    seen = []

    def name_it(column, command):
        seen.append((column, command))
        return f"pol_{len(seen)}"

    policy_require_match(Model.owner_id, config_value("app.user_id"), policy_name_format=name_it)

    assert [column for column, _ in seen] == [Model.__table__.c.owner_id] * 4
    assert {command for _, command in seen} == {
        PolicyCommands.SELECT,
        PolicyCommands.INSERT,
        PolicyCommands.UPDATE,
        PolicyCommands.DELETE,
    }


# -- end to end ----------------------------------------------------------------


def test_generated_create_sql_is_well_formed(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    select_policy = by_command(Model)[PolicyCommands.SELECT]

    assert select_policy.create_sql() == (
        "CREATE POLICY pol_documents_owner_id_select ON public.documents "
        "as PERMISSIVE\nfor SELECT\n"
        "using (public.documents.owner_id = current_setting('app.user_id', true))"
    )


def test_policies_reach_the_alembic_entities(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))

    signatures = {entity.signature for entity in registry.entities()}
    assert "pol_documents_owner_id_select" in signatures
    assert "pol_documents_owner_id_insert" in signatures


def test_declaring_twice_replaces_rather_than_duplicates(Model):
    """Names are derived, so a re-import must not double up."""
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    policy_require_match(Model.owner_id, config_value("app.other_id"))

    assert len(registry.get_policies(Model)) == 4
    assert "app.other_id" in by_command(Model)[PolicyCommands.SELECT].using


def test_two_columns_on_one_table_do_not_collide(Model):
    policy_require_match(Model.owner_id, config_value("app.user_id"))
    policy_require_match(Model.title, config_value("app.title"))

    assert len(registry.get_policies(Model)) == 8
