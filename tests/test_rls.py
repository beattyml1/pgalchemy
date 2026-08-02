"""RLS declaration via the base model, the decorator and Core tables."""
from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, MetaData, Table
from sqlalchemy.orm import DeclarativeBase, declarative_base

from pgalchemy import Policy, PolicyCommands, get_rls, is_rls_enabled, rls, rls_base
from pgalchemy.registry import registry
from pgalchemy.rls import RlsData, rls_for_table


def test_rls_base_enables_rls_on_every_subclass():
    Base = rls_base(declarative_base())

    class Thing(Base):
        __tablename__ = "things"
        id = Column(Integer, primary_key=True)

    assert is_rls_enabled(Thing)
    assert get_rls(Thing) == RlsData(active=True)


def test_rls_base_works_with_the_2_0_style_declarative_base():
    class Base(DeclarativeBase):
        pass

    Secure = rls_base(Base)

    class Thing(Secure):
        __tablename__ = "things_20"
        id = Column(Integer, primary_key=True)

    assert is_rls_enabled(Thing)


def test_rls_base_can_default_to_disabled():
    Base = rls_base(declarative_base(), default_active=False)

    class Thing(Base):
        __tablename__ = "opt_in_things"
        id = Column(Integer, primary_key=True)

    assert not is_rls_enabled(Thing)


def test_each_subclass_gets_its_own_rls_data():
    """Sibling models must not share mutable RLS state."""
    Base = rls_base(declarative_base())

    class A(Base):
        __tablename__ = "a"
        id = Column(Integer, primary_key=True)

    class B(Base):
        __tablename__ = "b"
        id = Column(Integer, primary_key=True)

    assert get_rls(A) is not get_rls(B)


def test_decorator_enables_rls_on_a_plain_base():
    Base = declarative_base()

    @rls()
    class Doc(Base):
        __tablename__ = "docs"
        id = Column(Integer, primary_key=True)

    assert is_rls_enabled(Doc)


def test_decorator_can_opt_a_model_out_of_an_rls_base():
    Base = rls_base(declarative_base())

    @rls(enabled=False)
    class OpenTable(Base):
        __tablename__ = "open_table"
        id = Column(Integer, primary_key=True)

    assert not is_rls_enabled(OpenTable)
    assert get_rls(OpenTable) == RlsData(active=False)


def test_decorator_records_force():
    Base = declarative_base()

    @rls(force=True)
    class Doc(Base):
        __tablename__ = "forced_docs"
        id = Column(Integer, primary_key=True)

    assert get_rls(Doc).force is True


def test_decorator_binds_the_policies_it_is_given():
    Base = declarative_base()
    unbound = Policy("pol_inline", for_=PolicyCommands.ALL, using="true")

    @rls(policies=[unbound])
    class Doc(Base):
        __tablename__ = "policy_docs"
        id = Column(Integer, primary_key=True)

    assert unbound.on is Doc
    assert unbound in registry.get_policies(Doc)


def test_rls_for_table_returns_the_table_it_was_given():
    table = Table("core_table", MetaData(), Column("id", Integer))

    result = rls_for_table()(table)

    assert result is table
    assert is_rls_enabled(table)


def test_rls_for_table_binds_policies():
    table = Table("core_policy_table", MetaData(), Column("id", Integer))
    unbound = Policy("pol_core", using="true")

    rls_for_table(policies=[unbound])(table)

    assert unbound.on is table
    assert unbound in registry.get_policies(table)


def test_rls_state_is_not_stored_in_table_info():
    """``Table.info`` is rendered verbatim into migration scripts.

    Anything non-literal placed there produces a migration file that does not
    parse, so RLS state must live in the registry instead.
    """
    Base = rls_base(declarative_base())

    class Thing(Base):
        __tablename__ = "info_free"
        id = Column(Integer, primary_key=True)

    assert Thing.__table__.info == {}


def test_registrations_survive_to_metadata_copies():
    """``env.py`` commonly rebuilds tables into a fresh MetaData."""
    Base = rls_base(declarative_base())

    class Thing(Base):
        __tablename__ = "copied"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    target = MetaData()
    copied = Thing.__table__.to_metadata(target)

    assert copied is not Thing.__table__
    assert is_rls_enabled(copied)


def test_lookup_tolerates_implicit_versus_explicit_public_schema():
    Base = rls_base(declarative_base())

    class Thing(Base):
        __tablename__ = "schema_flex"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    assert registry.get_rls((None, "schema_flex")) is not None
    assert registry.get_rls(("public", "schema_flex")) is not None


def test_unregistered_tables_report_no_rls():
    table = Table("never_declared", MetaData(), Column("id", Integer))

    assert get_rls(table) is None
    assert not is_rls_enabled(table)


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (RlsData(True), RlsData(True), True),
        (RlsData(True), RlsData(False), False),
        (RlsData(True, force=True), RlsData(True, force=False), False),
    ],
)
def test_rls_data_equality(left, right, expected):
    assert (left == right) is expected
