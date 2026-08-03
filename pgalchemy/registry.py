"""Central registry for the Postgres objects pgalchemy knows how to manage.

Everything pgalchemy generates -- RLS flags, policies, functions and views --
is recorded here so that the Alembic integration has a single place to look.

Registrations are keyed by ``(schema, table_name)`` rather than by ``Table``
identity on purpose: Alembic's ``env.py`` commonly rebuilds tables into a fresh
``MetaData`` with :meth:`~sqlalchemy.Table.to_metadata`, which produces brand
new ``Table`` objects. Keying by name keeps those copies pointing at the same
registrations.

RLS state is deliberately *not* stored in ``Table.info``. Alembic renders
``info=`` verbatim into generated migration scripts, so any non-literal object
placed there produces a migration file that will not parse.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

from sqlalchemy import Table
from sqlalchemy.orm import DeclarativeBase

if TYPE_CHECKING:  # pragma: no cover - typing only
    from alembic_utils.replaceable_entity import ReplaceableEntity

    from .functions import Function
    from .policy import Policy
    from .rls import RlsData
    from .views import View

TableKey = Tuple[Optional[str], str]

DEFAULT_SCHEMA = "public"


def table_key(target: Any) -> TableKey:
    """Normalise a model / table / name into a ``(schema, table_name)`` key."""
    table = resolve_table(target)
    if table is not None:
        return (table.schema, table.name)
    if isinstance(target, str):
        schema, _, name = target.rpartition(".")
        return (schema or None, name)
    if isinstance(target, tuple) and len(target) == 2:
        return (target[0], target[1])
    raise TypeError(
        f"Cannot determine a table from {target!r}. Expected a declarative model, "
        f"a Table, a 'schema.table' string or a (schema, table) tuple."
    )


def resolve_table(target: Any) -> Optional[Table]:
    """Return the :class:`~sqlalchemy.Table` for a model or table, else ``None``."""
    if isinstance(target, Table):
        return target
    if isinstance(target, type) and issubclass(target, DeclarativeBase):
        return target.__table__
    # ``declarative_base()`` produces classes that are not DeclarativeBase
    # subclasses, so fall back to duck typing on ``__table__``.
    table = getattr(target, "__table__", None)
    if isinstance(table, Table):
        return table
    return None


def qualified_name(key: TableKey) -> str:
    schema, name = key
    return f"{schema or DEFAULT_SCHEMA}.{name}"


class Registry:
    """Holds every pgalchemy declaration made by the importing application."""

    def __init__(self) -> None:
        self.rls: Dict[TableKey, "RlsData"] = {}
        # policies are keyed by name within a table so re-declaring a policy
        # replaces it rather than silently emitting a duplicate.
        self.policies: Dict[TableKey, Dict[str, "Policy"]] = {}
        self.functions: List["Function"] = []
        self.views: List["View"] = []
        # Policy declarations made against an abstract base's column, which have
        # no table yet. Expanded per concrete subclass -- see
        # ``pgalchemy.permission_patterns``.
        self.patterns: List[Any] = []

    # -- row level security -------------------------------------------------
    def register_rls(self, target: Any, data: "RlsData") -> "RlsData":
        self.rls[table_key(target)] = data
        return data

    def get_rls(self, target: Any) -> Optional["RlsData"]:
        key = table_key(target)
        found = self.rls.get(key)
        if found is not None:
            return found
        # Tolerate the implicit/explicit "public" schema mismatch.
        schema, name = key
        if schema is None:
            return self.rls.get((DEFAULT_SCHEMA, name))
        if schema == DEFAULT_SCHEMA:
            return self.rls.get((None, name))
        return None

    # -- policies -----------------------------------------------------------
    def register_policy(self, policy: "Policy") -> "Policy":
        self.policies.setdefault(table_key(policy.table), {})[policy.name] = policy
        return policy

    def get_policies(self, target: Any) -> List["Policy"]:
        return list(self.policies.get(table_key(target), {}).values())

    def iter_policies(self) -> Iterator["Policy"]:
        for by_name in self.policies.values():
            yield from by_name.values()

    # -- deferred patterns --------------------------------------------------
    def register_pattern(self, pattern: Any) -> Any:
        self.patterns.append(pattern)
        return pattern

    # -- functions & views --------------------------------------------------
    def register_function(self, function: "Function") -> "Function":
        self.functions.append(function)
        return function

    def register_view(self, view: "View") -> "View":
        self.views.append(view)
        return view

    # -- alembic ------------------------------------------------------------
    def entities(self, include_policies: bool = True) -> List["ReplaceableEntity"]:
        """Every declaration as an ``alembic_utils`` entity, ready to register.

        ``include_policies`` is off in the Alembic integration because pgalchemy
        compares policies itself -- see ``pgalchemy.alembic.register_entities``.
        """
        entities: List["ReplaceableEntity"] = []
        if include_policies:
            entities.extend(policy.to_entity() for policy in self.iter_policies())
        entities.extend(function.to_entity() for function in self.functions)
        entities.extend(view.to_entity() for view in self.views)
        return entities

    def clear(self) -> None:
        """Drop every registration. Primarily useful for test isolation."""
        self.rls.clear()
        self.policies.clear()
        self.functions.clear()
        self.views.clear()
        self.patterns.clear()


registry = Registry()
