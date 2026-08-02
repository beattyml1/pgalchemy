"""Reading policies back out of ``pg_policies`` and normalising definitions.

PostgreSQL rewrites policy expressions when it stores them -- ``id = 1``
comes back as ``(id = 1)``, casts get parenthesised, and so on. Comparing our
declared SQL against that text directly produces spurious differences, so the
declared policy is round-tripped through the database inside a savepoint and
the two *stored* forms are compared instead.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy import text

_SELECT_POLICIES = text(
    """
    SELECT policyname, permissive, roles, cmd, qual, with_check
    FROM pg_policies
    WHERE schemaname = :schema AND tablename = :table
    """
)


class PolicyState:
    """A policy as PostgreSQL currently stores it."""

    def __init__(self, name: str, permissive, roles, cmd, qual, with_check):
        self.name = name
        self.permissive = permissive
        self.roles = roles
        self.cmd = cmd
        self.qual = qual
        self.with_check = with_check

    @property
    def definition(self) -> str:
        parts = []
        if self.permissive is not None:
            parts.append(f"as {self.permissive}")
        if self.cmd is not None:
            parts.append(f"for {self.cmd}")
        if self.roles:
            parts.append(f"to {', '.join(sorted(self.roles))}")
        if self.qual is not None:
            parts.append(f"using {_parenthesised(self.qual)}")
        if self.with_check is not None:
            parts.append(f"with check {_parenthesised(self.with_check)}")
        return " ".join(parts)

    @property
    def comparable(self) -> str:
        return " ".join(self.definition.lower().split())

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"PolicyState({self.name!r}, {self.definition!r})"


def _parenthesised(expression: str) -> str:
    expression = expression.strip()
    return expression if expression.startswith("(") else f"({expression})"


def fetch_policies(connection, schema: Optional[str], table: str) -> Dict[str, PolicyState]:
    """Every policy currently on a table, keyed by name."""
    rows = connection.execute(
        _SELECT_POLICIES, {"schema": schema or "public", "table": table}
    ).fetchall()
    states = [PolicyState(*row) for row in rows]
    return {state.name: state for state in states}


def stored_form_of(connection, policy) -> Optional[PolicyState]:
    """How PostgreSQL *would* store ``policy``, without keeping the change.

    The policy is (re)created inside a savepoint that is always rolled back, so
    the comparison sees the same normalisation the live policy went through.
    Returns ``None`` when the round trip is not possible -- for instance when
    the table does not exist yet.
    """
    savepoint = connection.begin_nested()
    try:
        connection.execute(
            text(f"DROP POLICY IF EXISTS {policy.name} ON {policy.on_entity}")
        )
        connection.execute(text(policy.create_sql()))
        current = fetch_policies(connection, policy.schema, policy.table.name)
        return current.get(policy.name)
    except Exception:
        return None
    finally:
        savepoint.rollback()


def differs(connection, policy, live: PolicyState) -> bool:
    """Whether ``policy`` as declared differs from the ``live`` stored policy."""
    declared = stored_form_of(connection, policy)
    if declared is None:
        # Could not normalise; assume unchanged rather than churn the migration.
        return False
    return declared.comparable != live.comparable


def managed_policy_names(connection, schema: Optional[str], table: str) -> List[str]:
    return list(fetch_policies(connection, schema, table))
