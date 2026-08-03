"""Row level security declarations for models and tables."""
from __future__ import annotations

from typing import Any, Iterable, List, Optional, Type, TypeVar

from sqlalchemy import Table, event
from sqlalchemy.orm import DeclarativeBase

from .policy import Policy
from .registry import registry, resolve_table

ModelT = TypeVar("ModelT")


class RlsData:
    """Whether row level security should be on for a table, and its policies.

    ``force`` maps to ``ALTER TABLE ... FORCE ROW LEVEL SECURITY``, which also
    applies policies to the table owner.
    """

    def __init__(
        self,
        active: bool = True,
        force: bool = False,
        policies: Optional[Iterable[Policy]] = None,
    ):
        self.active = active
        self.force = force
        self.policies: List[Policy] = list(policies or [])

    def copy(self) -> "RlsData":
        return RlsData(self.active, self.force)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RlsData):
            return NotImplemented
        return (self.active, self.force) == (other.active, other.force)

    def __hash__(self) -> int:
        return hash((self.active, self.force))

    def __repr__(self) -> str:
        return f"RlsData(active={self.active!r}, force={self.force!r})"


def rls_base(Base: Type[Any], default_active: bool = True, force: bool = False):
    """Return an abstract base whose subclasses have RLS enabled by default.

    ``BaseModel = rls_base(declarative_base())`` -- every model inheriting from
    ``BaseModel`` is registered as needing row level security, unless it opts
    out with ``@rls(enabled=False)``.
    """

    class WithRls(Base):
        __abstract__ = True
        __rls__ = RlsData(default_active, force)

    @event.listens_for(WithRls, "instrument_class", propagate=True)
    def _register_rls_on_instrument(mapper, class_):  # noqa: ARG001 - event signature
        table = mapper.local_table
        if not isinstance(table, Table):
            return
        # Give each mapped class its own RlsData so that mutating one model's
        # settings never leaks into its siblings.
        data = class_.__dict__.get("__rls__")
        if data is None:
            inherited = getattr(class_, "__rls__", None)
            if inherited is None:
                return
            data = inherited.copy()
            class_.__rls__ = data
        registry.register_rls(table, data)

    return WithRls


def rls(
    enabled: bool = True,
    force: bool = False,
    policies: Optional[Iterable[Policy]] = None,
):
    """Class decorator enabling (or disabling) RLS on a single model.

    Intended for projects where most tables are *not* protected; prefer
    :func:`rls_base` otherwise so that new models are secure by default.
    """

    def wrapper(Model: Type[ModelT]) -> Type[ModelT]:
        data = RlsData(enabled, force, policies)
        Model.__rls__ = data

        def register(table: Table) -> None:
            registry.register_rls(table, data)
            for item in data.policies:
                item.bind(Model)

        table = resolve_table(Model)
        if table is not None:
            register(table)
        else:
            # Applied before the mapper built the table (unusual, but possible
            # with deferred/imperative mapping) -- finish the job on instrument.
            @event.listens_for(Model, "instrument_class")
            def _register_rls_on_instrument(mapper, class_):  # noqa: ARG001
                if isinstance(mapper.local_table, Table):
                    register(mapper.local_table)

        return Model

    return wrapper


def rls_for_table(
    enabled: bool = True,
    force: bool = False,
    policies: Optional[Iterable[Policy]] = None,
):
    """Enable RLS on a Core :class:`~sqlalchemy.Table` (no ORM model required).

    Usable as a decorator or as a plain call: ``rls_for_table()(my_table)``.
    """

    def wrapper(table: Table) -> Table:
        data = RlsData(enabled, force, policies)
        registry.register_rls(table, data)
        for item in data.policies:
            item.bind(table)
        return table

    return wrapper


def get_rls(target: Any) -> Optional[RlsData]:
    """The :class:`RlsData` registered for a model or table, if any."""
    return registry.get_rls(target)


def is_rls_enabled(target: Any) -> bool:
    data = registry.get_rls(target)
    return bool(data and data.active)
