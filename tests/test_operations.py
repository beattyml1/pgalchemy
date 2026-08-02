"""The SQL and the migration-script source produced by pgalchemy's operations."""
from alembic.autogenerate import render_python_code
from alembic.operations import ops

import pytest

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
from pgalchemy.alembic.operations.cls import grant_column_sql, revoke_column_sql
from pgalchemy.alembic.operations.policy import create_policy_sql, drop_policy_sql
from pgalchemy.alembic.operations.rls import (
    disable_rls_sql,
    enable_rls_sql,
    force_rls_sql,
    no_force_rls_sql,
)


class TestRlsSql:
    def test_enable(self):
        assert (
            enable_rls_sql(EnableRlsOp("users", schema="public"))
            == "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;"
        )

    def test_enable_without_a_schema(self):
        assert (
            enable_rls_sql(EnableRlsOp("users"))
            == "ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
        )

    def test_disable(self):
        assert (
            disable_rls_sql(DisableRlsOp("users", schema="public"))
            == "ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;"
        )

    def test_force(self):
        assert (
            force_rls_sql(ForceRlsOp("users", schema="public"))
            == "ALTER TABLE public.users FORCE ROW LEVEL SECURITY;"
        )

    def test_no_force(self):
        assert (
            no_force_rls_sql(NoForceRlsOp("users", schema="public"))
            == "ALTER TABLE public.users NO FORCE ROW LEVEL SECURITY;"
        )


class TestColumnPrivilegeSql:
    def test_grant(self):
        op = ColGrantOp("users", "SELECT", "email", "app_reader", schema="public")
        assert grant_column_sql(op) == "GRANT SELECT (email) ON public.users TO app_reader;"

    def test_revoke(self):
        op = ColRevokeOp("users", "UPDATE", "email", "app_user", schema="public")
        assert (
            revoke_column_sql(op) == "REVOKE UPDATE (email) ON public.users FROM app_user;"
        )


class TestPolicySql:
    def test_create(self):
        op = CreatePolicyOp("pol_x", "users", "as PERMISSIVE\nfor SELECT\nusing (true)", schema="public")
        assert create_policy_sql(op) == (
            "CREATE POLICY pol_x ON public.users as PERMISSIVE\nfor SELECT\nusing (true);"
        )

    def test_drop(self):
        op = DropPolicyOp("pol_x", "users", schema="public")
        assert drop_policy_sql(op) == "DROP POLICY pol_x ON public.users;"

    def test_without_a_schema(self):
        assert drop_policy_sql(DropPolicyOp("pol_x", "users")) == "DROP POLICY pol_x ON users;"


class TestReversibility:
    def test_enable_reverses_to_disable(self):
        reversed_op = EnableRlsOp("users", schema="public").reverse()
        assert isinstance(reversed_op, DisableRlsOp)
        assert (reversed_op.table_name, reversed_op.schema) == ("users", "public")

    def test_disable_reverses_to_enable(self):
        assert isinstance(DisableRlsOp("users").reverse(), EnableRlsOp)

    def test_force_reverses_to_no_force(self):
        assert isinstance(ForceRlsOp("users").reverse(), NoForceRlsOp)

    def test_grant_reverses_to_revoke_with_every_argument_preserved(self):
        reversed_op = ColGrantOp("users", "SELECT", "email", "reader", schema="s").reverse()

        assert isinstance(reversed_op, ColRevokeOp)
        assert reversed_op.table_name == "users"
        assert reversed_op.operation == "SELECT"
        assert reversed_op.column == "email"
        assert reversed_op.role == "reader"
        assert reversed_op.schema == "s"

    def test_revoke_reverses_to_grant(self):
        assert isinstance(ColRevokeOp("t", "SELECT", "c", "r").reverse(), ColGrantOp)

    def test_create_policy_reverses_to_drop_carrying_the_definition(self):
        reversed_op = CreatePolicyOp("pol", "users", "for SELECT", schema="s").reverse()

        assert isinstance(reversed_op, DropPolicyOp)
        assert reversed_op.definition == "for SELECT"
        assert isinstance(reversed_op.reverse(), CreatePolicyOp)

    def test_dropping_a_policy_without_a_definition_cannot_be_reversed(self):
        with pytest.raises(NotImplementedError, match="definition"):
            DropPolicyOp("pol", "users").reverse()


class TestRendering:
    """Rendered operations must be valid, executable migration source."""

    def render(self, operations):
        return render_python_code(ops.UpgradeOps(ops=operations))

    def test_enable_rls_renders(self):
        assert "op.enable_rls('users', schema='public')" in self.render(
            [EnableRlsOp("users", schema="public")]
        )

    def test_enable_rls_with_force_renders_the_flag(self):
        assert "op.enable_rls('users', schema='public', force=True)" in self.render(
            [EnableRlsOp("users", schema="public", force=True)]
        )

    def test_disable_rls_renders(self):
        assert "op.disable_rls('users', schema='public')" in self.render(
            [DisableRlsOp("users", schema="public")]
        )

    def test_force_and_no_force_render(self):
        rendered = self.render([ForceRlsOp("users"), NoForceRlsOp("users")])
        assert "op.force_rls('users', schema=None)" in rendered
        assert "op.no_force_rls('users', schema=None)" in rendered

    def test_column_grant_and_revoke_render(self):
        rendered = self.render(
            [
                ColGrantOp("users", "SELECT", "email", "reader", schema="public"),
                ColRevokeOp("users", "UPDATE", "email", "writer", schema="public"),
            ]
        )
        assert "op.grant_column('users', 'SELECT', 'email', 'reader', schema='public')" in rendered
        assert (
            "op.revoke_column('users', 'UPDATE', 'email', 'writer', schema='public')" in rendered
        )

    def test_policy_operations_render(self):
        rendered = self.render(
            [
                CreatePolicyOp("pol_x", "users", "for SELECT\nusing (true)", schema="public"),
                DropPolicyOp("pol_y", "users", schema="public", definition="for ALL"),
            ]
        )
        assert (
            "op.create_policy('pol_x', 'users', 'for SELECT\\nusing (true)', schema='public')"
            in rendered
        )
        assert (
            "op.drop_policy('pol_y', 'users', schema='public', definition='for ALL')" in rendered
        )

    def test_rendered_source_is_syntactically_valid_python(self):
        import ast
        import textwrap

        rendered = self.render(
            [
                EnableRlsOp("users", schema="public", force=True),
                ColGrantOp("users", "SELECT", "email", "reader", schema="public"),
            ]
        )
        # render_python_code indents for a migration's upgrade() body.
        ast.parse("def upgrade():\n" + textwrap.indent(textwrap.dedent(rendered), "    "))


class TestOperationsAreRegisteredWithAlembic:
    def test_op_namespace_exposes_every_directive(self):
        from alembic.operations import Operations

        for name in (
            "enable_rls",
            "disable_rls",
            "force_rls",
            "no_force_rls",
            "grant_column",
            "revoke_column",
            "create_policy",
            "drop_policy",
        ):
            assert hasattr(Operations, name), f"op.{name} is not registered"
