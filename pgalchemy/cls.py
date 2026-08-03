"""Column level security: per-role GRANT/REVOKE on individual columns."""
from __future__ import annotations

from enum import Enum
from typing import Any, List, NamedTuple, Union

from sqlalchemy import Column, Table

from pgalchemy.policy import PolicyCommands
from pgalchemy.registry import resolve_table

#: Key under which column privilege rules are stashed on ``Column.info``.
#: ``Column.info`` is safe to use here -- unlike ``Table.info`` it is not
#: rendered into generated migration scripts.
COLUMN_INFO_KEY = "pgalchemy_cls"


class All(Enum):
    All = "__ALL__"

    def __str__(self) -> str:  # pragma: no cover - display only
        return "*"


class GrantAction(Enum):
    GRANT = "GRANT"
    REVOKE = "REVOKE"

    def __str__(self) -> str:
        return self.value


class ColumnSecurityRule(NamedTuple):
    """A single declared privilege, e.g. ``GRANT SELECT (col) TO role``."""

    action: str
    operation: str
    role: str


def _operation_name(operation: Union[PolicyCommands, str]) -> str:
    return operation.value if isinstance(operation, PolicyCommands) else str(operation)


def _add_rule(col: Column, action: GrantAction, operation: Any, role: str) -> Column:
    # No call to manage_cls_for_combo here: at decoration time the column is not
    # yet attached to a table and may not even have a name, so there is nothing
    # to key a combination on. Declaring a rule is itself the statement that
    # pgalchemy manages this role/column pair -- see column_is_managed.
    rules: List[ColumnSecurityRule] = col.info.setdefault(COLUMN_INFO_KEY, [])
    rules.append(ColumnSecurityRule(action.value, _operation_name(operation), role))
    return col


def deny_for_column(operation: Union[PolicyCommands, str], role: str):
    """Revoke ``operation`` on the decorated column from ``role``.

    ``owner_id = deny_for_column(PolicyCommands.UPDATE, 'app_user')(Column(Integer))``
    """

    def wrapper(col: Column) -> Column:
        return _add_rule(col, GrantAction.REVOKE, operation, role)

    return wrapper


def allow_for_column(operation: Union[PolicyCommands, str], role: str):
    """Grant ``operation`` on the decorated column to ``role``."""

    def wrapper(col: Column) -> Column:
        return _add_rule(col, GrantAction.GRANT, operation, role)

    return wrapper


def column_rules(column: Column) -> List[ColumnSecurityRule]:
    """Privilege rules declared on ``column`` (empty when there are none)."""
    info = getattr(column, "info", None) or {}
    return list(info.get(COLUMN_INFO_KEY, ()))


_cls_registry: List[tuple] = []


def column_is_managed(role: str, column: Column) -> bool:
    """Whether pgalchemy owns the privileges for ``role`` on ``column``.

    Unmanaged combinations are left alone so that grants made outside of
    pgalchemy are never silently revoked. A column that declares a rule for
    ``role`` is managed for that role by definition; broader ownership can be
    declared with :func:`manage_cls_for_combo`.
    """
    if any(rule.role == role for rule in column_rules(column)):
        return True

    table = getattr(column, "table", None)
    schema = getattr(table, "schema", None)
    table_name = getattr(table, "name", None)
    return any(
        (r in (role, All.All))
        and (s in (schema, All.All))
        and (t in (table_name, All.All))
        and (c in (column.name, All.All))
        for r, s, t, c in _cls_registry
    )


def manage_cls_for_combo(
    role: Union[str, All] = All.All,
    schema: Union[str, All, None] = All.All,
    table: Union[Table, str, All, Any] = All.All,
    column: Union[Column, str, All] = All.All,
):
    """Declare that pgalchemy manages column privileges for a combination.

    Any of ``role``/``schema``/``table``/``column`` may be left as
    :attr:`All.All` to mean "every value".
    """
    resolved = resolve_table(table)
    if resolved is not None:
        table = resolved

    if isinstance(column, Column):
        if column.table is not None:
            table = column.table
        column = column.name

    if isinstance(table, Table):
        schema = table.schema
        table = table.name

    combo = (role, schema, table, column)
    if combo not in _cls_registry:
        _cls_registry.append(combo)
    return combo


def clear_managed_combos() -> None:
    """Reset the managed-combination registry (test isolation helper)."""
    _cls_registry.clear()
