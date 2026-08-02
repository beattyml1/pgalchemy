"""Alembic autogenerate support for RLS and column level security.

Importing this module registers the comparators and renderers, so ``env.py``
only needs ``import pgalchemy.alembic.comparator``.
"""
from __future__ import annotations

from typing import List, Optional, Sequence

from alembic.autogenerate import comparators, renderers
from sqlalchemy import Column, Table, text

from ..cls import ColumnSecurityRule, column_is_managed, column_rules
from ..registry import registry
from ..rls import RlsData
from .column_privilege import ColumnPrivilege
from .operations import (
    ColGrantOp,
    ColRevokeOp,
    CreatePolicyOp,
    DisableRlsOp,
    DropPolicyOp,
    EnableRlsOp,
    ForceRlsOp,
    NoForceRlsOp,
)
from .policy_state import differs, fetch_policies

# --------------------------------------------------------------------------
# Renderers -- turn our operations back into migration script source
# --------------------------------------------------------------------------


@renderers.dispatch_for(EnableRlsOp)
def render_enable_rls(autogen_context, op):
    if op.force:
        return "op.enable_rls(%r, schema=%r, force=True)" % (op.table_name, op.schema)
    return "op.enable_rls(%r, schema=%r)" % (op.table_name, op.schema)


@renderers.dispatch_for(DisableRlsOp)
def render_disable_rls(autogen_context, op):
    return "op.disable_rls(%r, schema=%r)" % (op.table_name, op.schema)


@renderers.dispatch_for(ForceRlsOp)
def render_force_rls(autogen_context, op):
    return "op.force_rls(%r, schema=%r)" % (op.table_name, op.schema)


@renderers.dispatch_for(NoForceRlsOp)
def render_no_force_rls(autogen_context, op):
    return "op.no_force_rls(%r, schema=%r)" % (op.table_name, op.schema)


@renderers.dispatch_for(ColGrantOp)
def render_grant_column(autogen_context, op):
    return "op.grant_column(%r, %r, %r, %r, schema=%r)" % (
        op.table_name,
        op.operation,
        op.column,
        op.role,
        op.schema,
    )


@renderers.dispatch_for(ColRevokeOp)
def render_revoke_column(autogen_context, op):
    return "op.revoke_column(%r, %r, %r, %r, schema=%r)" % (
        op.table_name,
        op.operation,
        op.column,
        op.role,
        op.schema,
    )


@renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(autogen_context, op):
    return "op.create_policy(%r, %r, %r, schema=%r)" % (
        op.policy_name,
        op.table_name,
        op.definition,
        op.schema,
    )


@renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(autogen_context, op):
    if op.definition is None:
        return "op.drop_policy(%r, %r, schema=%r)" % (
            op.policy_name,
            op.table_name,
            op.schema,
        )
    return "op.drop_policy(%r, %r, schema=%r, definition=%r)" % (
        op.policy_name,
        op.table_name,
        op.schema,
        op.definition,
    )


# --------------------------------------------------------------------------
# Comparators
# --------------------------------------------------------------------------


@comparators.dispatch_for("table")
def compare_pgalchemy_table(
    autogen_context,
    modify_ops,
    schemaname,
    tablename,
    conn_table: Optional[Table],
    metadata_table: Optional[Table],
):
    """Compare RLS and column privileges for one table.

    Alembic dispatches this for added tables (``conn_table is None``), removed
    tables (``metadata_table is None``) and tables present in both.
    """
    if metadata_table is None:
        # The table is being dropped; DROP TABLE takes its RLS with it.
        return

    schema = metadata_table.schema if metadata_table.schema is not None else schemaname

    compare_rls(
        autogen_context, modify_ops, schema, tablename, conn_table, metadata_table
    )
    compare_policies(
        autogen_context, modify_ops, schema, tablename, conn_table, metadata_table
    )
    compare_column_security(
        autogen_context, modify_ops, schema, tablename, conn_table, metadata_table
    )


def compare_rls(
    autogen_context, modify_ops, schemaname, tablename, conn_table, metadata_table
):
    rls: Optional[RlsData] = registry.get_rls(metadata_table)
    if rls is None:
        return

    if conn_table is None:
        # Brand new table: nothing in the database to compare against, so state
        # the desired configuration outright.
        if rls.active:
            modify_ops.ops.append(
                EnableRlsOp(tablename, schema=schemaname, force=rls.force)
            )
        return

    enabled_db, forced_db = get_table_rls_data(autogen_context, schemaname, tablename)
    if enabled_db is None:
        return

    compare_rls_enabled(modify_ops, rls, enabled_db, forced_db, schemaname, tablename)


def compare_rls_enabled(
    modify_ops, rls: RlsData, rls_enabled_db, rls_forced_db, schemaname, tablename
):
    if rls.active and not rls_enabled_db:
        modify_ops.ops.append(
            EnableRlsOp(tablename, schema=schemaname, force=rls.force)
        )
    elif not rls.active and rls_enabled_db:
        modify_ops.ops.append(DisableRlsOp(tablename, schema=schemaname))
    elif rls.active and rls_enabled_db and rls.force != bool(rls_forced_db):
        op = ForceRlsOp if rls.force else NoForceRlsOp
        modify_ops.ops.append(op(tablename, schema=schemaname))


def get_table_rls_data(autogen_context, schemaname, tablename):
    """``(relrowsecurity, relforcerowsecurity)`` for a table, or ``(None, None)``."""
    connection = getattr(autogen_context, "connection", None)
    if connection is None:
        # Offline (``--sql``) mode: there is nothing to inspect.
        return None, None

    results = connection.execute(
        text(
            """
            SELECT c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = :schema AND c.relname = :table
        """
        ),
        {"schema": schemaname or "public", "table": tablename},
    )
    row = results.fetchone()
    if row is None:
        return None, None
    return row[0], row[1]


def compare_policies(
    autogen_context, modify_ops, schemaname, tablename, conn_table, metadata_table
):
    """Create, drop and replace policies so the database matches the declarations.

    Policies are handled here rather than through ``alembic_utils`` so that they
    can be created in the same migration as the table they protect --
    alembic_utils has to reach the live table to work out what a policy means,
    which is impossible before the table exists.
    """
    declared = {policy.name: policy for policy in registry.get_policies(metadata_table)}
    connection = getattr(autogen_context, "connection", None)

    if conn_table is None:
        # New table: everything declared has to be created, nothing to drop.
        for policy in declared.values():
            modify_ops.ops.append(_create_op(policy, tablename, schemaname))
        return

    if connection is None:
        # Offline (``--sql``) mode: nothing to compare against.
        return

    live = fetch_policies(connection, schemaname, tablename)

    # pgalchemy only prunes policies on tables it has been told it owns.
    owns_table = bool(declared) or registry.get_rls(metadata_table) is not None

    for name, policy in declared.items():
        if name not in live:
            modify_ops.ops.append(_create_op(policy, tablename, schemaname))
        elif differs(connection, policy, live[name]):
            modify_ops.ops.append(
                DropPolicyOp(
                    name,
                    tablename,
                    schema=schemaname,
                    definition=live[name].definition,
                )
            )
            modify_ops.ops.append(_create_op(policy, tablename, schemaname))

    if not owns_table:
        return

    for name, state in live.items():
        if name not in declared:
            modify_ops.ops.append(
                DropPolicyOp(
                    name, tablename, schema=schemaname, definition=state.definition
                )
            )


def _create_op(policy, tablename, schemaname) -> CreatePolicyOp:
    return CreatePolicyOp(
        policy.name,
        tablename,
        policy.definition_sql(),
        schema=schemaname,
    )


def compare_column_security(
    autogen_context, modify_ops, schemaname, tablename, conn_table, metadata_table
):
    """Emit GRANT/REVOKE operations for columns that declare privilege rules."""
    connection = getattr(autogen_context, "connection", None)

    for column in metadata_table.columns:
        rules = column_rules(column)
        if not rules:
            continue

        if conn_table is None or connection is None:
            db_privileges: List[ColumnPrivilege] = []
        else:
            db_privileges = ColumnPrivilege.get_for_column(
                connection, schemaname, tablename, column.name
            )

        compare_cls_enabled(
            modify_ops, rules, db_privileges, schemaname, tablename, column.name, column
        )


def compare_cls_enabled(
    modify_ops,
    code_privileges: Sequence[ColumnSecurityRule],
    db_privileges: Sequence[ColumnPrivilege],
    schemaname,
    tablename,
    colname,
    metadata_column: Column,
):
    for rule in code_privileges or ():
        action, operation, role = rule
        if not column_is_managed(role, column=metadata_column):
            continue

        exists = any(x.is_same(operation, role) for x in db_privileges)
        if action == "GRANT" and not exists:
            modify_ops.ops.append(
                ColGrantOp(
                    table_name=tablename,
                    operation=operation,
                    column=colname,
                    role=role,
                    schema=schemaname,
                )
            )
        elif action == "REVOKE" and exists:
            modify_ops.ops.append(
                ColRevokeOp(
                    table_name=tablename,
                    operation=operation,
                    column=colname,
                    role=role,
                    schema=schemaname,
                )
            )
