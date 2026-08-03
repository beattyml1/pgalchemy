"""End-to-end autogeneration against a real PostgreSQL.

Skipped automatically when no database is reachable. To run it::

    docker compose up -d
    pytest -m integration

Set ``PGALCHEMY_TEST_DSN`` to point at a different server.
"""
from __future__ import annotations

import textwrap

import pytest
from alembic.autogenerate import produce_migrations, render_python_code
from alembic.migration import MigrationContext
from alembic.operations import Operations, ops
from sqlalchemy import text

import pgalchemy.alembic  # noqa: F401  (registers comparators and renderers)
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
from pgalchemy.registry import registry
from tests.models import build_models

pytestmark = pytest.mark.integration

SCHEMA = "rls_it"  # must not match SQLAlchemy's "pg_%" system-schema filter


@pytest.fixture()
def models():
    return build_models(schema=SCHEMA)


@pytest.fixture()
def connection(pg_connection):
    """A clean, empty schema inside a transaction that is rolled back after.

    The demo models grant a column privilege to ``app_reader``, so that role
    has to exist before any migration runs. CREATE ROLE is transactional in
    PostgreSQL, so the rollback takes it away again.
    """
    pg_connection.execute(text(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE'))
    pg_connection.execute(text(f'CREATE SCHEMA "{SCHEMA}"'))
    if not pg_connection.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = 'app_reader'")
    ).scalar():
        pg_connection.execute(text("CREATE ROLE app_reader"))
    return pg_connection


def migration_context(connection, metadata) -> MigrationContext:
    return MigrationContext.configure(
        connection,
        opts={"target_metadata": metadata, "include_schemas": True},
    )


def upgrade_ops_for(connection, metadata):
    context = migration_context(connection, metadata)
    return produce_migrations(context, metadata).upgrade_ops


def flatten(operations):
    """Expand containers such as ModifyTableOps into individual directives."""
    for operation in operations:
        nested = getattr(operation, "ops", None)
        if nested is None:
            yield operation
        else:
            yield from flatten(nested)


def apply_migration(connection, metadata):
    """Run everything autogenerate produced, the way ``alembic upgrade`` would."""
    context = migration_context(connection, metadata)
    upgrade_ops = produce_migrations(context, metadata).upgrade_ops
    operations = Operations(context)
    for operation in flatten(upgrade_ops.ops):
        operations.invoke(operation)
    return upgrade_ops


def test_autogenerate_emits_rls_operations(connection, models):
    code = render_python_code(upgrade_ops_for(connection, models.metadata))

    assert "op.create_table('users'" in code
    assert f"op.enable_rls('users', schema='{SCHEMA}')" in code
    assert f"op.enable_rls('secure_documents', schema='{SCHEMA}', force=True)" in code
    # public_settings opted out with @rls(enabled=False), so leave it alone.
    assert "op.enable_rls('public_settings'" not in code


def test_generated_migration_script_is_importable_python(connection, models):
    """``Table.info`` holding a Python object used to produce unparseable scripts."""
    code = render_python_code(upgrade_ops_for(connection, models.metadata))

    assert "info={" not in code
    compile(
        "def upgrade():\n" + textwrap.indent(textwrap.dedent(code), "    "),
        "<migration>",
        "exec",
    )


def test_autogenerate_emits_column_grants(connection, models):
    code = render_python_code(upgrade_ops_for(connection, models.metadata))

    assert (
        f"op.grant_column('users', 'SELECT', 'is_admin', 'app_reader', schema='{SCHEMA}')"
        in code
    )


def test_running_the_migration_enables_rls_in_the_database(connection, models):
    apply_migration(connection, models.metadata)

    rows = connection.execute(
        text(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = :schema AND c.relkind = 'r'
            """
        ),
        {"schema": SCHEMA},
    ).fetchall()
    state = {name: (enabled, forced) for name, enabled, forced in rows}

    assert state["users"] == (True, False)
    assert state["posts"] == (True, False)
    assert state["comments"] == (True, False)
    assert state["secure_documents"] == (True, True)
    assert state["public_settings"] == (False, False)


def test_a_second_autogenerate_run_finds_nothing_left_to_do(connection, models):
    """Applying the migration must leave no table, RLS or privilege differences.

    Only pgalchemy's own directives are inspected: alembic_utils contributes a
    schema-level comparator of its own whose scope is a separate concern.
    """
    apply_migration(connection, models.metadata)

    second = list(flatten(upgrade_ops_for(connection, models.metadata).ops))
    rendered = render_python_code(upgrade_ops_for(connection, models.metadata))

    pgalchemy_ops = [
        operation
        for operation in second
        if isinstance(
            operation,
            (
                EnableRlsOp,
                DisableRlsOp,
                ForceRlsOp,
                NoForceRlsOp,
                ColGrantOp,
                ColRevokeOp,
                CreatePolicyOp,
                DropPolicyOp,
            ),
        )
    ]
    table_ops = [
        operation
        for operation in second
        if isinstance(operation, (ops.CreateTableOp, ops.DropTableOp))
    ]

    assert pgalchemy_ops == [], rendered
    assert table_ops == [], rendered


def live_policy_names(connection):
    return {
        row[0]
        for row in connection.execute(
            text("SELECT policyname FROM pg_policies WHERE schemaname = :schema"),
            {"schema": SCHEMA},
        )
    }


def test_policies_are_created_in_the_same_migration_as_their_tables(connection, models):
    """No second pass required: alembic_utils cannot do this, pgalchemy can."""
    apply_migration(connection, models.metadata)

    assert live_policy_names(connection) == {p.name for p in models.policies}


def test_generated_policy_sql_matches_what_was_declared(connection, models):
    apply_migration(connection, models.metadata)

    rows = dict(
        connection.execute(
            text(
                "SELECT policyname, permissive FROM pg_policies "
                "WHERE schemaname = :schema AND tablename = 'users'"
            ),
            {"schema": SCHEMA},
        ).fetchall()
    )

    assert rows["users_select_policy"] == "PERMISSIVE"
    assert rows["users_delete_policy"] == "RESTRICTIVE"


def test_a_policy_removed_from_the_models_is_dropped(connection, models):
    apply_migration(connection, models.metadata)

    removed = next(p for p in models.policies if p.name == "users_select_policy")
    del registry.policies[("public" if SCHEMA is None else SCHEMA, "users")][removed.name]

    second = list(flatten(upgrade_ops_for(connection, models.metadata).ops))
    drops = [
        operation
        for operation in second
        if isinstance(operation, DropPolicyOp) and operation.policy_name == removed.name
    ]

    assert len(drops) == 1


def test_a_changed_policy_is_replaced(connection, models):
    apply_migration(connection, models.metadata)

    changed = next(p for p in models.policies if p.name == "users_select_policy")
    changed.using = "is_admin = true"

    second = list(flatten(upgrade_ops_for(connection, models.metadata).ops))
    touching = [
        operation
        for operation in second
        if getattr(operation, "policy_name", None) == "users_select_policy"
    ]

    assert [type(op) for op in touching] == [DropPolicyOp, CreatePolicyOp]


def test_generated_function_and_view_sql_are_accepted_by_postgres(connection, models):
    apply_migration(connection, models.metadata)

    for declared in registry.functions:
        if declared.schema == SCHEMA:
            connection.execute(text(declared.create_sql()))
    for declared in registry.views:
        if declared.schema == SCHEMA:
            connection.execute(text(declared.create_sql()))

    assert connection.execute(text(f"SELECT {SCHEMA}.post_count(1)")).scalar() == 0
    assert connection.execute(text(f"SELECT count(*) FROM {SCHEMA}.published_posts")).scalar() == 0


def test_column_grant_is_applied_to_the_database(connection, models):
    apply_migration(connection, models.metadata)

    granted = connection.execute(
        text(
            """
            SELECT count(*) FROM information_schema.column_privileges
            WHERE table_schema = :schema AND table_name = 'users'
              AND column_name = 'is_admin' AND grantee = 'app_reader'
              AND privilege_type = 'SELECT'
            """
        ),
        {"schema": SCHEMA},
    ).scalar()

    assert granted == 1
