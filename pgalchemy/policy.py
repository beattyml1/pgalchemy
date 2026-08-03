"""Row level security policies."""
from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Optional, Sequence, Type, Union

from alembic_utils.pg_policy import PGPolicy
from sqlalchemy import Table
from sqlalchemy.orm import DeclarativeBase

from .expressions import render_expression
from .registry import DEFAULT_SCHEMA, registry, resolve_table


class PolicyType(Enum):
    PERMISSIVE = "PERMISSIVE"
    RESTRICTIVE = "RESTRICTIVE"

    def __str__(self) -> str:
        return self.value


class PolicyCommands(Enum):
    ALL = "ALL"
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

    def __str__(self) -> str:
        return self.value


PolicyTarget = Union[Type[DeclarativeBase], Table, None]


class Policy:
    """A PostgreSQL ``CREATE POLICY`` declaration.

    Declaring a policy registers it, so simply constructing one at import time
    is enough for the Alembic integration to pick it up::

        Policy("pol_posts_select", on=Post, for_=PolicyCommands.SELECT,
               using="user_id = current_setting('app.user_id')::int")

    ``on`` may be omitted when the policy is handed to the :func:`~pgalchemy.rls.rls`
    decorator, which binds it to the model it decorates.
    """

    def __init__(
        self,
        name: str,
        on: PolicyTarget = None,
        as_: Optional[PolicyType] = PolicyType.PERMISSIVE,
        for_: Optional[PolicyCommands] = PolicyCommands.ALL,
        to: Union[str, Iterable[str], None] = None,
        using: Any = None,
        with_check: Any = None,
    ):
        self.name = name
        self.as_ = as_
        self.for_ = for_
        self.to: Sequence[str] = _coerce_roles(to)
        self.using = render_expression(using)
        self.with_check = render_expression(with_check)
        self.on = None
        if on is not None:
            self.bind(on)

    # -- binding ------------------------------------------------------------
    def bind(self, target: PolicyTarget) -> "Policy":
        """Attach this policy to a model or table and register it."""
        table = resolve_table(target)
        if table is None:
            raise TypeError(
                f"Policy {self.name!r} cannot be applied to {target!r}: expected a "
                f"declarative model or a Table"
            )
        self.on = target
        registry.register_policy(self)
        return self

    @property
    def table(self) -> Table:
        if self.on is None:
            raise ValueError(
                f"Policy {self.name!r} is not bound to a table. Pass on=<Model> or "
                f"hand it to the @rls(policies=[...]) decorator."
            )
        table = resolve_table(self.on)
        if table is None:  # pragma: no cover - guarded by bind()
            raise TypeError(f"Unsupported policy target {self.on!r}")
        return table

    @property
    def schema(self) -> str:
        return self.table.schema or DEFAULT_SCHEMA

    @property
    def on_entity(self) -> str:
        return f"{self.schema}.{self.table.name}"

    # -- SQL ----------------------------------------------------------------
    def _as_fragment(self) -> str:
        return f"as {self.as_.value}\n" if self.as_ else ""

    def _for_fragment(self) -> str:
        return f"for {self.for_.value}\n" if self.for_ else ""

    def _to_fragment(self) -> str:
        return f"to {', '.join(self.to)}\n" if self.to else ""

    def _using_fragment(self) -> str:
        return f"using ({self.using})\n" if self.using else ""

    def _with_check_fragment(self) -> str:
        return f"with check ({self.with_check})\n" if self.with_check else ""

    def definition_sql(self) -> str:
        """The policy body, i.e. everything after ``CREATE POLICY name ON table``."""
        return (
            self._as_fragment()
            + self._for_fragment()
            + self._to_fragment()
            + self._using_fragment()
            + self._with_check_fragment()
        ).strip()

    def create_sql(self) -> str:
        return f"CREATE POLICY {self.name} ON {self.on_entity} {self.definition_sql()}"

    def drop_sql(self) -> str:
        return f"DROP POLICY {self.name} ON {self.on_entity}"

    def to_entity(self) -> PGPolicy:
        """The equivalent ``alembic_utils`` entity, for autogenerate support."""
        return PGPolicy(
            schema=self.schema,
            signature=self.name,
            on_entity=self.on_entity,
            definition=self.definition_sql(),
        )

    # Retained for backwards compatibility with the original API.
    attach = to_entity

    def __repr__(self) -> str:
        target = self.on_entity if self.on is not None else "<unbound>"
        return f"Policy({self.name!r}, on={target})"


def _coerce_roles(to: Union[str, Iterable[str], None]) -> Sequence[str]:
    if to is None:
        return ()
    if isinstance(to, str):
        return (to,)
    return tuple(to)


def policy(*policies: Policy):
    """Class decorator that binds one or more policies to the decorated model.

    ``@policy(Policy("pol_x", for_=PolicyCommands.ALL, using="..."))`` is the
    equivalent of passing ``on=`` to each policy explicitly.
    """

    def wrapper(model):
        for item in policies:
            item.bind(model)
        return model

    return wrapper
