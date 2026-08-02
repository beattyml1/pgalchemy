"""Policy declaration, SQL generation and registration."""
from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table
from sqlalchemy.orm import declarative_base

from pgalchemy import Policy, PolicyCommands, PolicyType, policy
from pgalchemy.registry import registry


@pytest.fixture()
def Model():
    Base = declarative_base()

    class Widget(Base):
        __tablename__ = "widgets"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)
        name = Column(String(50))

    return Widget


def test_name_is_the_first_positional_argument(Model):
    """The README spells policies ``Policy("name", on=Model, ...)``."""
    declared = Policy("pol_widgets_select", on=Model, for_=PolicyCommands.SELECT, using="true")
    assert declared.name == "pol_widgets_select"
    assert declared.on is Model


def test_definition_sql_contains_every_clause(Model):
    declared = Policy(
        "pol_widgets_update",
        on=Model,
        as_=PolicyType.RESTRICTIVE,
        for_=PolicyCommands.UPDATE,
        to=["app_user", "app_admin"],
        using="owner_id = 1",
        with_check="owner_id = 1",
    )
    definition = declared.definition_sql()

    assert "as RESTRICTIVE" in definition
    assert "for UPDATE" in definition
    assert "to app_user, app_admin" in definition
    assert "using (owner_id = 1)" in definition
    assert "with check (owner_id = 1)" in definition


def test_enum_values_are_not_rendered_as_python_reprs(Model):
    declared = Policy("pol", on=Model, as_=PolicyType.PERMISSIVE, for_=PolicyCommands.DELETE)
    definition = declared.definition_sql()

    assert "PolicyType." not in definition
    assert "PolicyCommands." not in definition


def test_omitted_clauses_are_omitted_not_stringified(Model):
    """A missing ``using``/``with_check`` must not leak the string "None"."""
    declared = Policy("pol_widgets_insert", on=Model, for_=PolicyCommands.INSERT)

    assert declared.using is None
    assert declared.with_check is None
    assert "None" not in declared.definition_sql()
    assert "using" not in declared.definition_sql()


def test_create_and_drop_sql(Model):
    declared = Policy("pol_widgets_all", on=Model, using="true")

    assert declared.create_sql().startswith("CREATE POLICY pol_widgets_all ON public.widgets ")
    assert declared.drop_sql() == "DROP POLICY pol_widgets_all ON public.widgets"


def test_sqlalchemy_expressions_are_compiled_with_literal_binds(Model):
    declared = Policy("pol_expr", on=Model, using=Model.owner_id == 42)

    assert declared.using is not None
    assert "42" in declared.using
    assert ":" not in declared.using  # no leftover bind parameter placeholders


def test_table_property_resolves_models_and_core_tables(Model):
    core_table = Table("gadgets", MetaData(), Column("id", Integer))

    assert Policy("a", on=Model).table is Model.__table__
    assert Policy("b", on=core_table).table is core_table


def test_declaring_a_policy_registers_it(Model):
    declared = Policy("pol_registered", on=Model, using="true")

    assert declared in registry.get_policies(Model)
    assert declared in list(registry.iter_policies())


def test_redeclaring_a_name_replaces_rather_than_duplicates(Model):
    Policy("pol_dup", on=Model, using="true")
    second = Policy("pol_dup", on=Model, using="false")

    matching = [p for p in registry.get_policies(Model) if p.name == "pol_dup"]
    assert matching == [second]


def test_unbound_policy_can_be_bound_later(Model):
    declared = Policy("pol_later", for_=PolicyCommands.SELECT, using="true")

    assert declared not in registry.get_policies(Model)
    with pytest.raises(ValueError, match="not bound"):
        _ = declared.table

    declared.bind(Model)
    assert declared in registry.get_policies(Model)


def test_policy_decorator_binds_to_the_decorated_model():
    Base = declarative_base()
    unbound = Policy("pol_decorated", for_=PolicyCommands.ALL, using="true")

    @policy(unbound)
    class Thing(Base):
        __tablename__ = "things"
        id = Column(Integer, primary_key=True)

    assert unbound.on is Thing
    assert unbound in registry.get_policies(Thing)


def test_binding_to_something_that_is_not_a_table_raises():
    with pytest.raises(TypeError):
        Policy("pol_bad", on="not a model")  # type: ignore[arg-type]


def test_to_entity_produces_a_matching_alembic_utils_policy(Model):
    declared = Policy(
        "pol_entity", on=Model, for_=PolicyCommands.SELECT, using="owner_id = 1"
    )
    entity = declared.to_entity()

    assert entity.schema == "public"
    assert entity.signature == "pol_entity"
    assert entity.on_entity == "public.widgets"
    assert "for SELECT" in entity.definition


def test_schema_defaults_to_public_when_the_table_has_none():
    Base = declarative_base()

    class NoSchema(Base):
        __tablename__ = "no_schema"
        id = Column(Integer, primary_key=True)

    declared = Policy("pol_default_schema", on=NoSchema, using="true")
    assert declared.schema == "public"
    assert declared.on_entity == "public.no_schema"
