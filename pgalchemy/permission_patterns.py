"""Reusable policy patterns.

Spelling out ownership by hand means writing four policies per table and
remembering which clause each command accepts: ``INSERT`` takes only
``with check``, ``DELETE`` only ``using``, and ``UPDATE`` needs both -- given
only ``using``, a caller can update a row they own into one they do not. The
helpers here generate the whole set from a single declaration.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import Column

from .expressions import render_expression
from .policy import Policy, PolicyCommands, PolicyType


def default_policy_name_format(column: Column, command: PolicyCommands) -> str:
    """Name a generated policy ``pol_<table>_<column>_<command>``.

    The result is lowercased because PostgreSQL folds unquoted identifiers when
    it stores them. ``pg_policies.policyname`` would come back as
    ``pol_widgets_owner_id_select`` regardless of what was written, and the
    Alembic comparator matches declared policies against that catalog by name --
    so an uppercased name never matches, and autogenerate emits a duplicate
    ``CREATE POLICY`` on every run.

    Only the bare table name is used. ``str(column.table)`` renders a
    schema-qualified table as ``app.widgets``, and the embedded dot would make
    the policy name parse as a schema reference.
    """
    return f"pol_{column.table.name}_{column.name}_{command}".lower()


def policy_require_match(
        column: Column,
        getter: Any,
        require: Any | None = None,
        override: Any | None = None,
        policy_type: PolicyType = PolicyType.PERMISSIVE,
        policy_name_format: Callable[[Column, PolicyCommands], str] = default_policy_name_format):
    """Restrict every row of ``column``'s table to those where ``column == getter``.

    Declares four policies -- one each for SELECT, INSERT, UPDATE and DELETE --
    on the table owning ``column``. ``getter`` is whatever identifies the
    caller, most often a session setting read back with
    :func:`~pgalchemy.config.config_value`::

        policy_require_match(Document.owner_id, config_value('app.user_id').cast(Integer))

    which yields, among the other three::

        CREATE POLICY pol_documents_owner_id_select ON public.documents
        as PERMISSIVE for SELECT
        using (public.documents.owner_id = CAST(current_setting('app.user_id', true) AS INTEGER))

    **Cast the getter to the column's type.** ``current_setting`` returns
    ``text``, so matching it against a non-text column fails with ``operator
    does not exist: integer = text``. Nothing catches this until the migration
    runs, because the policy body is only text until PostgreSQL parses it.

    ``override`` is OR-ed into the match, for the escape hatch an admin role
    needs::

        policy_require_match(
            Document.owner_id,
            config_value('app.user_id').cast(Integer),
            override=config_value('app.is_admin').cast(Boolean),
        )

    Pass ``policy_type=PolicyType.RESTRICTIVE`` to make the match a requirement
    rather than a grant. PostgreSQL OR-s permissive policies together, so a
    permissive match declared alongside another permissive policy *widens*
    access; restrictive policies are AND-ed and always narrow it.

    ``getter`` and ``override`` must be SQLAlchemy expressions or Python
    literals -- both are rendered with literal binds. Raw SQL strings need
    :func:`~sqlalchemy.text` or :func:`~sqlalchemy.literal_column`, since a bare
    ``str`` would be compiled as a quoted string value.

    Nothing is returned; constructing a :class:`~pgalchemy.policy.Policy`
    registers it, which is all the Alembic integration needs.
    """
    table = column.table

    clause = column == getter
    if require is not None:
        clause = clause & require
    if override is not None:
        clause = clause | override

    # render_expression compiles with literal binds. Plain str() would leave
    # ``:current_setting_1`` placeholders in the policy body, and Policy passes
    # strings through verbatim, so they would reach the migration as-is.
    matches = render_expression(clause)

    PC = PolicyCommands

    Policy(policy_name_format(column, PC.SELECT), on=table, as_=policy_type, for_=PC.SELECT, using=matches)
    Policy(policy_name_format(column, PC.DELETE), on=table, as_=policy_type, for_=PC.DELETE, using=matches)
    Policy(policy_name_format(column, PC.UPDATE), on=table, as_=policy_type, for_=PC.UPDATE, using=matches, with_check=matches)
    Policy(policy_name_format(column, PC.INSERT), on=table, as_=policy_type, for_=PC.INSERT, with_check=matches)
