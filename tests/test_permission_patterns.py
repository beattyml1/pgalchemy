"""Generated ownership policies: naming, clause placement and rendering."""
from __future__ import annotations

import re

import pytest
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, literal_column
from sqlalchemy.orm import declarative_base

from pgalchemy import PolicyCommands, PolicyType
from pgalchemy.config import config_value
from pgalchemy.permission_patterns import (
    DeferredMatch,
    default_policy_name_format,
    patterns_for,
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


# -- declaring against an abstract base ----------------------------------------


def test_abstract_base_applies_to_every_concrete_subclass():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Doc(Owned):
        __tablename__ = "docs"
        id = Column(Integer, primary_key=True)

    class Note(Owned):
        __tablename__ = "notes"
        id = Column(Integer, primary_key=True)

    assert {p.name for p in registry.get_policies(Doc)} == {
        "pol_docs_owner_id_select",
        "pol_docs_owner_id_insert",
        "pol_docs_owner_id_update",
        "pol_docs_owner_id_delete",
    }
    assert len(registry.get_policies(Note)) == 4
    assert "notes.owner_id" in by_command(Note)[PolicyCommands.SELECT].using


def test_models_defined_before_the_declaration_are_swept():
    """Declaration order must not matter -- a model imported before the pattern
    is declared would otherwise be silently unprotected."""
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    class Early(Owned):
        __tablename__ = "early"
        id = Column(Integer, primary_key=True)

    assert registry.get_policies(Early) == []

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    assert len(registry.get_policies(Early)) == 4


def test_plain_mixin_works_as_well_as_an_abstract_base():
    Base = declarative_base()

    class OwnedMixin:
        owner_id = Column(Integer)

    policy_require_match(OwnedMixin.owner_id, config_value("app.user_id").cast(Integer))

    class Doc(OwnedMixin, Base):
        __tablename__ = "docs_mixin"
        id = Column(Integer, primary_key=True)

    assert len(registry.get_policies(Doc)) == 4


def test_concrete_column_still_applies_immediately(Model):
    """The public function keeps the original behaviour for a bound column."""
    result = policy_require_match(Model.owner_id, config_value("app.user_id").cast(Integer))

    assert result is None
    assert len(registry.get_policies(Model)) == 4
    assert registry.patterns == []


def test_deferring_returns_and_registers_the_pattern():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    pattern = policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    assert isinstance(pattern, DeferredMatch)
    assert pattern in registry.patterns


def test_pattern_is_recorded_on_the_declaring_class():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    pattern = policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Doc(Owned):
        __tablename__ = "docs_owner"
        id = Column(Integer, primary_key=True)

    assert Owned.__dict__["__pgalchemy_patterns__"] == [pattern]
    assert patterns_for(Doc) == [pattern]
    assert pattern.owner is Owned


def test_patterns_accumulate_from_several_bases():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    class Tenanted(Owned):
        __abstract__ = True
        tenant_id = Column(Integer)

    owner_pattern = policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))
    tenant_pattern = policy_require_match(Tenanted.tenant_id, config_value("app.tenant").cast(Integer))

    class Doc(Tenanted):
        __tablename__ = "docs_both"
        id = Column(Integer, primary_key=True)

    assert set(patterns_for(Doc)) == {owner_pattern, tenant_pattern}
    assert len(registry.get_policies(Doc)) == 8
    # the declaring class keeps only its own, never its parent's
    assert Owned.__dict__["__pgalchemy_patterns__"] == [owner_pattern]
    assert Tenanted.__dict__["__pgalchemy_patterns__"] == [tenant_pattern]


def test_unnamed_column_is_matched_by_identity_not_name():
    """``Column(Integer)`` on an abstract base has ``name is None`` until it is
    copied onto a subclass's table, so name lookup cannot work."""
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    assert Owned.owner_id.name is None
    assert Owned.owner_id.table is None

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Doc(Owned):
        __tablename__ = "docs_ident"
        id = Column(Integer, primary_key=True)

    assert "pol_docs_ident_owner_id_select" in {p.name for p in registry.get_policies(Doc)}


def test_explicitly_named_column_resolves_to_that_name():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner = Column("owner_id", Integer)

    policy_require_match(Owned.owner, config_value("app.user_id").cast(Integer))

    class Doc(Owned):
        __tablename__ = "docs_named"
        id = Column(Integer, primary_key=True)

    assert "pol_docs_named_owner_id_select" in {p.name for p in registry.get_policies(Doc)}


def test_options_carry_through_to_every_subclass():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    policy_require_match(
        Owned.owner_id,
        config_value("app.user_id").cast(Integer),
        override=literal_column("current_user = 'admin'"),
        policy_type=PolicyType.RESTRICTIVE,
    )

    class Doc(Owned):
        __tablename__ = "docs_opts"
        id = Column(Integer, primary_key=True)

    for policy in registry.get_policies(Doc):
        assert policy.as_ is PolicyType.RESTRICTIVE
        assert "current_user = 'admin'" in (policy.using or policy.with_check)


def test_unrelated_models_are_untouched():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Unrelated(Base):
        __tablename__ = "unrelated"
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)  # same name, different declaration

    assert registry.get_policies(Unrelated) == []


def test_joined_table_child_without_the_column_is_skipped():
    """The child's own table has no owner_id, so there is nothing to match on.
    Note this leaves the child table itself unprotected against a direct
    ``SELECT * FROM mgr`` -- ORM queries filter via the join to the parent."""
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Emp(Owned):
        __tablename__ = "emp"
        id = Column(Integer, primary_key=True)
        kind = Column(String(20))
        __mapper_args__ = {"polymorphic_on": kind, "polymorphic_identity": "emp"}

    class Mgr(Emp):
        __tablename__ = "mgr"
        id = Column(Integer, ForeignKey("emp.id"), primary_key=True)
        __mapper_args__ = {"polymorphic_identity": "mgr"}

    assert len(registry.get_policies(Emp)) == 4
    assert registry.get_policies(Mgr) == []


def test_single_table_inheritance_does_not_duplicate():
    Base = declarative_base()

    class Owned(Base):
        __abstract__ = True
        owner_id = Column(Integer)

    policy_require_match(Owned.owner_id, config_value("app.user_id").cast(Integer))

    class Item(Owned):
        __tablename__ = "items"
        id = Column(Integer, primary_key=True)
        kind = Column(String(20))
        __mapper_args__ = {"polymorphic_on": kind, "polymorphic_identity": "item"}

    class Special(Item):
        __mapper_args__ = {"polymorphic_identity": "special"}

    assert len(registry.get_policies(Item)) == 4
    assert len(registry.get_policies(Special)) == 4  # same table, deduped by name
