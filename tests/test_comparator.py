"""Autogenerate comparison logic, driven against a stubbed connection.

These exercise the real comparator entry point that Alembic dispatches to, so
they cover the decision table without needing a database.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from alembic.operations import ops
from sqlalchemy import Column, Integer, MetaData, String, Table
from sqlalchemy.orm import declarative_base

import pgalchemy.alembic  # noqa: F401  (registers comparators and renderers)
from pgalchemy import (
    Policy,
    PolicyCommands,
    allow_for_column,
    deny_for_column,
    rls,
    rls_base,
)
from pgalchemy.alembic.comparator import compare_pgalchemy_table
from pgalchemy.alembic.operations import (
    ColGrantOp,
    ColRevokeOp,
    CreatePolicyOp,
    DisableRlsOp,
    DropPolicyOp,
    EnableRlsOp,
    ForceRlsOp,
    NoForceRlsOp,
)

PRIVILEGE_COLUMNS = (
    "grantor",
    "grantee",
    "table_catalog",
    "table_schema",
    "table_name",
    "column_name",
    "privilege_type",
    "is_grantable",
)


class FakeRow(tuple):
    """Just enough of ``sqlalchemy.Row`` for the code under test."""

    def __new__(cls, mapping: Dict[str, Any]):
        row = super().__new__(cls, tuple(mapping.values()))
        row._mapping_dict = dict(mapping)
        return row

    def _asdict(self) -> Dict[str, Any]:
        return dict(self._mapping_dict)


class FakeResult:
    def __init__(self, rows: List[FakeRow]):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class FakeSavepoint:
    def __init__(self, connection):
        self.connection = connection

    def rollback(self):
        self.connection.recreated = False


class FakeConnection:
    """Answers the queries the comparator issues.

    ``policies`` is what ``pg_policies`` currently holds. ``normalized`` is what
    it would hold after the declared policy is re-created, which is how the
    comparator tells a genuine change from PostgreSQL's own rewriting; it
    defaults to ``policies``, i.e. "nothing changed".
    """

    def __init__(
        self,
        rls_row=None,
        privileges: Optional[List[Dict[str, Any]]] = None,
        policies: Optional[List[tuple]] = None,
        normalized: Optional[List[tuple]] = None,
    ):
        self.rls_row = rls_row
        self.privileges = privileges or []
        self.policies = policies or []
        self.normalized = normalized
        self.recreated = False
        self.queries: List[str] = []

    def begin_nested(self):
        return FakeSavepoint(self)

    def execute(self, statement, params=None):
        sql = str(statement)
        self.queries.append(sql)
        upper = sql.upper()
        if upper.startswith("CREATE POLICY"):
            self.recreated = True
            return FakeResult([])
        if upper.startswith("DROP POLICY"):
            return FakeResult([])
        if "pg_class" in sql:
            return FakeResult([FakeRow(self.rls_row)] if self.rls_row else [])
        if "pg_policies" in sql:
            rows = (
                self.normalized
                if (self.recreated and self.normalized is not None)
                else self.policies
            )
            return FakeResult(list(rows))
        if "column_privileges" in sql:
            rows = [
                FakeRow({key: privilege.get(key) for key in PRIVILEGE_COLUMNS})
                for privilege in self.privileges
                if params is None or privilege.get("column_name") == params.get("column")
            ]
            return FakeResult(rows)
        raise AssertionError(f"unexpected query: {sql}")


def policy_row(name, permissive="PERMISSIVE", roles=None, cmd="ALL", qual=None, with_check=None):
    """A ``pg_policies`` row as PostgreSQL would return it."""
    return (name, permissive, roles, cmd, qual, with_check)


class FakeAutogenContext:
    def __init__(self, connection=None):
        self.connection = connection


def db_rls(enabled: bool, forced: bool = False):
    return {"relrowsecurity": enabled, "relforcerowsecurity": forced}


def run(metadata_table, *, conn_table=None, connection=None, schema="public"):
    """Dispatch the comparator the way Alembic does and return the ops it added."""
    tablename = (metadata_table if metadata_table is not None else conn_table).name
    modify_ops = ops.ModifyTableOps(tablename, [], schema=schema)
    compare_pgalchemy_table(
        FakeAutogenContext(connection),
        modify_ops,
        schema,
        tablename,
        conn_table,
        metadata_table,
    )
    return modify_ops.ops


def existing(name="widgets", schema="public"):
    """A stand-in for the table reflected from the database."""
    return Table(name, MetaData(), Column("id", Integer), schema=schema)


@pytest.fixture()
def SecureModel():
    Base = rls_base(declarative_base())

    class Widget(Base):
        __tablename__ = "widgets"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    return Widget


class TestNewTables:
    def test_rls_is_enabled_for_a_newly_created_table(self, SecureModel):
        emitted = run(SecureModel.__table__, conn_table=None)

        assert len(emitted) == 1
        assert isinstance(emitted[0], EnableRlsOp)
        assert emitted[0].table_name == "widgets"
        assert emitted[0].schema == "public"

    def test_force_is_carried_through(self):
        Base = declarative_base()

        @rls(force=True)
        class Doc(Base):
            __tablename__ = "forced"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        emitted = run(Doc.__table__, conn_table=None)

        assert emitted[0].force is True

    def test_a_table_that_opted_out_gets_nothing(self):
        Base = rls_base(declarative_base())

        @rls(enabled=False)
        class Open(Base):
            __tablename__ = "open_table"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        assert run(Open.__table__, conn_table=None) == []

    def test_a_table_pgalchemy_knows_nothing_about_gets_nothing(self):
        plain = Table("plain", MetaData(), Column("id", Integer), schema="public")

        assert run(plain, conn_table=None) == []

    def test_new_tables_are_not_queried_for_state_that_cannot_exist_yet(self, SecureModel):
        connection = FakeConnection()
        run(SecureModel.__table__, conn_table=None, connection=connection)

        assert connection.queries == []


class TestExistingTables:
    def test_rls_wanted_but_not_enabled_yields_enable(self, SecureModel):
        connection = FakeConnection(rls_row=db_rls(enabled=False))

        emitted = run(SecureModel.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [EnableRlsOp]

    def test_rls_already_enabled_yields_nothing(self, SecureModel):
        connection = FakeConnection(rls_row=db_rls(enabled=True))

        assert run(SecureModel.__table__, conn_table=existing(), connection=connection) == []

    def test_rls_no_longer_wanted_yields_disable(self):
        Base = rls_base(declarative_base())

        @rls(enabled=False)
        class Open(Base):
            __tablename__ = "widgets"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        connection = FakeConnection(rls_row=db_rls(enabled=True))

        emitted = run(Open.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [DisableRlsOp]

    def test_force_added_yields_force(self):
        Base = declarative_base()

        @rls(force=True)
        class Doc(Base):
            __tablename__ = "widgets"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        connection = FakeConnection(rls_row=db_rls(enabled=True, forced=False))

        emitted = run(Doc.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [ForceRlsOp]

    def test_force_removed_yields_no_force(self, SecureModel):
        connection = FakeConnection(rls_row=db_rls(enabled=True, forced=True))

        emitted = run(SecureModel.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [NoForceRlsOp]

    def test_a_table_missing_from_the_database_is_skipped(self, SecureModel):
        connection = FakeConnection(rls_row=None)

        assert run(SecureModel.__table__, conn_table=existing(), connection=connection) == []

    def test_offline_mode_emits_nothing_for_existing_tables(self, SecureModel):
        """``alembic upgrade --sql`` has no connection to inspect."""
        assert run(SecureModel.__table__, conn_table=existing(), connection=None) == []


class TestDroppedTables:
    def test_nothing_is_emitted_when_the_model_is_gone(self):
        emitted = run(None, conn_table=existing())

        assert emitted == []


class TestPolicies:
    """Policies are compared by pgalchemy, not alembic_utils.

    That is what lets a policy be created in the same migration as the table it
    protects -- alembic_utils has to reach the live table to interpret a policy,
    which is impossible before that table exists.
    """

    def model(self, tablename="widgets"):
        Base = rls_base(declarative_base())

        class Widget(Base):
            __tablename__ = tablename
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)
            owner_id = Column(Integer)

        return Widget

    def test_policies_are_created_alongside_a_new_table(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")

        emitted = run(Widget.__table__, conn_table=None)

        created = [op for op in emitted if isinstance(op, CreatePolicyOp)]
        assert len(created) == 1
        assert created[0].policy_name == "pol_select"
        assert created[0].table_name == "widgets"
        assert "for SELECT" in created[0].definition

    def test_a_create_is_ordered_after_the_rls_enable(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")

        emitted = run(Widget.__table__, conn_table=None)

        assert [type(op).__name__ for op in emitted] == ["EnableRlsOp", "CreatePolicyOp"]

    def test_a_missing_policy_is_created_on_an_existing_table(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")
        connection = FakeConnection(rls_row=db_rls(enabled=True), policies=[])

        emitted = run(Widget.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [CreatePolicyOp]

    def test_an_unchanged_policy_produces_nothing(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")
        live = [policy_row("pol_select", cmd="SELECT", qual="true")]
        connection = FakeConnection(rls_row=db_rls(enabled=True), policies=live)

        assert run(Widget.__table__, conn_table=existing(), connection=connection) == []

    def test_a_changed_policy_is_dropped_and_recreated(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="owner_id = 1")
        connection = FakeConnection(
            rls_row=db_rls(enabled=True),
            policies=[policy_row("pol_select", cmd="SELECT", qual="true")],
            normalized=[policy_row("pol_select", cmd="SELECT", qual="(owner_id = 1)")],
        )

        emitted = run(Widget.__table__, conn_table=existing(), connection=connection)

        assert [type(op) for op in emitted] == [DropPolicyOp, CreatePolicyOp]
        assert emitted[0].policy_name == "pol_select"

    def test_postgres_rewriting_alone_is_not_treated_as_a_change(self):
        """``owner_id = 1`` comes back as ``(owner_id = 1)``; that is not a diff."""
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="owner_id = 1")
        stored = [policy_row("pol_select", cmd="SELECT", qual="(owner_id = 1)")]
        connection = FakeConnection(
            rls_row=db_rls(enabled=True), policies=stored, normalized=stored
        )

        assert run(Widget.__table__, conn_table=existing(), connection=connection) == []

    def test_an_undeclared_policy_on_a_managed_table_is_dropped(self):
        Widget = self.model()
        Policy("pol_keep", on=Widget, for_=PolicyCommands.SELECT, using="true")
        connection = FakeConnection(
            rls_row=db_rls(enabled=True),
            policies=[
                policy_row("pol_keep", cmd="SELECT", qual="true"),
                policy_row("pol_stale", cmd="DELETE", qual="false"),
            ],
        )

        emitted = run(Widget.__table__, conn_table=existing(), connection=connection)

        dropped = [op for op in emitted if isinstance(op, DropPolicyOp)]
        assert [op.policy_name for op in dropped] == ["pol_stale"]

    def test_a_dropped_policy_keeps_its_definition_so_it_can_be_reversed(self):
        Widget = self.model()
        Policy("pol_keep", on=Widget, for_=PolicyCommands.SELECT, using="true")
        connection = FakeConnection(
            rls_row=db_rls(enabled=True),
            policies=[
                policy_row("pol_keep", cmd="SELECT", qual="true"),
                policy_row("pol_stale", cmd="DELETE", qual="false"),
            ],
        )

        emitted = run(Widget.__table__, conn_table=existing(), connection=connection)
        dropped = next(op for op in emitted if isinstance(op, DropPolicyOp))

        assert dropped.definition is not None
        assert isinstance(dropped.reverse(), CreatePolicyOp)

    def test_policies_on_tables_pgalchemy_does_not_manage_are_left_alone(self):
        """Never revoke access on a table the user did not hand to pgalchemy."""
        Base = declarative_base()

        class Foreign(Base):
            __tablename__ = "foreign_table"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        connection = FakeConnection(
            rls_row=db_rls(enabled=True),
            policies=[policy_row("someone_elses_policy", cmd="ALL", qual="true")],
        )

        emitted = run(
            Foreign.__table__, conn_table=existing("foreign_table"), connection=connection
        )

        assert emitted == []

    def test_offline_mode_emits_no_policy_changes_for_existing_tables(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")

        assert run(Widget.__table__, conn_table=existing(), connection=None) == []

    def test_dropped_tables_take_their_policies_with_them(self):
        Widget = self.model()
        Policy("pol_select", on=Widget, for_=PolicyCommands.SELECT, using="true")

        assert run(None, conn_table=existing()) == []


class TestColumnPrivileges:
    def build(self, decorator, tablename):
        Base = declarative_base()

        class Doc(Base):
            __tablename__ = tablename
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)
            secret = decorator(Column(String(20)))

        return Doc

    def test_a_grant_is_emitted_for_a_new_table(self):
        Doc = self.build(allow_for_column(PolicyCommands.SELECT, "reader"), "cls_new")

        emitted = run(Doc.__table__, conn_table=None)

        grants = [op for op in emitted if isinstance(op, ColGrantOp)]
        assert len(grants) == 1
        assert (grants[0].column, grants[0].operation, grants[0].role) == (
            "secret",
            "SELECT",
            "reader",
        )

    def test_an_existing_grant_is_left_alone(self):
        Doc = self.build(allow_for_column(PolicyCommands.SELECT, "reader"), "cls_existing")
        connection = FakeConnection(
            rls_row=db_rls(enabled=False),
            privileges=[
                {"column_name": "secret", "privilege_type": "SELECT", "grantee": "reader"}
            ],
        )

        emitted = run(
            Doc.__table__,
            conn_table=existing("cls_existing"),
            connection=connection,
        )

        assert [op for op in emitted if isinstance(op, ColGrantOp)] == []

    def test_a_revoke_is_emitted_only_when_the_privilege_is_present(self):
        Doc = self.build(deny_for_column(PolicyCommands.UPDATE, "writer"), "cls_revoke")
        connection = FakeConnection(
            rls_row=db_rls(enabled=False),
            privileges=[
                {"column_name": "secret", "privilege_type": "UPDATE", "grantee": "writer"}
            ],
        )

        emitted = run(
            Doc.__table__, conn_table=existing("cls_revoke"), connection=connection
        )

        revokes = [op for op in emitted if isinstance(op, ColRevokeOp)]
        assert len(revokes) == 1
        assert revokes[0].column == "secret"

    def test_a_revoke_for_a_privilege_that_is_not_there_is_a_no_op(self):
        Doc = self.build(deny_for_column(PolicyCommands.UPDATE, "writer"), "cls_absent")
        connection = FakeConnection(rls_row=db_rls(enabled=False), privileges=[])

        emitted = run(
            Doc.__table__, conn_table=existing("cls_absent"), connection=connection
        )

        assert [op for op in emitted if isinstance(op, ColRevokeOp)] == []

    def test_columns_without_rules_are_never_queried(self):
        Base = declarative_base()

        class Doc(Base):
            __tablename__ = "cls_none"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        connection = FakeConnection(rls_row=db_rls(enabled=False))
        run(Doc.__table__, conn_table=existing("cls_none"), connection=connection)

        assert not any("column_privileges" in query for query in connection.queries)
