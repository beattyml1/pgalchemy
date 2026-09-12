"""Reusable policy patterns.

Spelling out ownership by hand means writing four policies per table and
remembering which clause each command accepts: ``INSERT`` takes only
``with check``, ``DELETE`` only ``using``, and ``UPDATE`` needs both -- given
only ``using``, a caller can update a row they own into one they do not. The
helpers here generate the whole set from a single declaration.

:func:`policy_require_match` accepts either a concrete column, which it acts on
immediately, or a column declared on an abstract base, which it records and
replays against every concrete model that inherits it.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import Column, Table, event
from sqlalchemy.orm import Mapper

from .expressions import render_expression
from .policy import Policy, PolicyCommands, PolicyType
from .registry import registry

#: Attribute under which a base class records the patterns declared against its
#: columns. Set on the class that *declares* the column, so ordinary attribute
#: inheritance makes it visible to every subclass.
PATTERN_ATTR = "__pgalchemy_patterns__"


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


def _policy_require_match(
        column: Column,
        getter: Any,
        require: Any | None = None,
        override: Any | None = None,
        policy_type: PolicyType = PolicyType.PERMISSIVE,
        policy_name_format: Callable[[Column, PolicyCommands], str] = default_policy_name_format):
    """Restrict every row of ``column``'s table to those where ``column == getter``.

    The concrete half of :func:`policy_require_match`: ``column`` must already
    be attached to a table. Call the public function instead, which routes here
    or defers depending on what it is handed.

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


class DeferredMatch:
    """A :func:`policy_require_match` whose column has no table yet.

    Declared against an abstract base or mixin, then replayed against every
    concrete model that inherits the column.

    The column is tracked by **object identity**, not by name. A
    ``Column(Integer)`` on an abstract base has ``name`` of ``None`` until
    SQLAlchemy attaches a copy of it to a subclass's table, so there is nothing
    else to match on. Identity survives that copy only on the declaring class,
    which is why :meth:`locate` walks the MRO rather than reading ``__table__``.
    """

    def __init__(self, column: Column, options: Dict[str, Any]):
        self.column = column
        self.options = options
        self.owner: Optional[type] = None

    def locate(self, class_: type) -> Optional[Tuple[type, str]]:
        """``(declaring class, attribute name)`` if ``class_`` inherits this column."""
        for klass in class_.__mro__:
            for name, value in vars(klass).items():
                if value is self.column:
                    return klass, name
        return None

    def apply_to(self, class_: type, table: Table) -> bool:
        """Declare the policies on ``table``. False if this pattern does not apply."""
        located = self.locate(class_)
        if located is None:
            return False
        owner, attribute = located
        self._remember_on(owner)

        # ``table.c`` is keyed by Column.key, which declarative sets to the
        # attribute name. An explicitly named Column keeps its own name.
        concrete = table.c.get(attribute)
        if concrete is None and self.column.name:
            concrete = table.c.get(self.column.name)
        if concrete is None:
            # The column lives on another table in the hierarchy -- a
            # joined-table inheritance child, for instance.
            return False

        _policy_require_match(concrete, **self.options)
        return True

    def _remember_on(self, owner: type) -> None:
        """Record this pattern on the class that declares the column.

        Kept in the declaring class's own ``__dict__`` so that appending to one
        base's list never mutates a parent's.
        """
        self.owner = owner
        patterns = owner.__dict__.get(PATTERN_ATTR)
        if patterns is None:
            patterns = []
            setattr(owner, PATTERN_ATTR, patterns)
        if self not in patterns:
            patterns.append(self)

    def __repr__(self) -> str:
        owner = self.owner.__name__ if self.owner is not None else "<unresolved>"
        return f"DeferredMatch(owner={owner}, column={self.column!r})"


def policy_require_match(
        column: Column,
        getter: Any,
        require: Any | None = None,
        override: Any | None = None,
        policy_type: PolicyType = PolicyType.PERMISSIVE,
        policy_name_format: Callable[[Column, PolicyCommands], str] = default_policy_name_format):
    """Require ``column == getter`` on ``column``'s table, or on every table that inherits it.

    Given a column that already belongs to a table, this declares the four
    policies immediately -- see :func:`_policy_require_match` for the full
    description of ``getter``, ``require``, ``override`` and ``policy_type``.

    Given a column declared on an abstract base or a mixin, there is no table
    to act on yet, so the declaration is recorded and replayed against each
    concrete model that inherits the column::

        class Owned(Base):
            __abstract__ = True
            owner_id = Column(Integer)

        policy_require_match(Owned.owner_id, config_value('app.user_id').cast(Integer))

        class Document(Owned):     # gets pol_documents_owner_id_{select,insert,update,delete}
            __tablename__ = 'documents'
            id = Column(Integer, primary_key=True)

    Declaration order does not matter: models defined before the call are swept
    immediately, and models defined after are caught by a mapper event.

    Returns the :class:`DeferredMatch` when it defers, otherwise ``None``.
    """
    options = dict(
        getter=getter,
        require=require,
        override=override,
        policy_type=policy_type,
        policy_name_format=policy_name_format,
    )

    if getattr(column, "table", None) is not None:
        _policy_require_match(column, **options)
        return None

    pattern = DeferredMatch(column, options)
    registry.register_pattern(pattern)
    for class_, table in mapped_classes():
        pattern.apply_to(class_, table)
    return pattern


def patterns_for(class_: type) -> List[DeferredMatch]:
    """Every deferred pattern ``class_`` inherits, nearest base last."""
    found: List[DeferredMatch] = []
    for klass in class_.__mro__:
        for pattern in klass.__dict__.get(PATTERN_ATTR, ()):
            if pattern not in found:
                found.append(pattern)
    return found


def mapped_classes() -> List[Tuple[type, Table]]:
    """Already-mapped classes and their local tables.

    Reads the class managers rather than ``registry.mappers`` so that declaring
    a pattern never triggers ``configure_mappers()``. Forcing configuration at
    import time would raise for any model whose relationships name a class that
    has not been imported yet.
    """
    try:
        from sqlalchemy.orm import mapperlib

        registries = mapperlib._all_registries()
    except Exception:  # pragma: no cover - private API moved
        return []

    mapped: List[Tuple[type, Table]] = []
    for reg in registries:
        for manager in list(getattr(reg, "_managers", ())):
            mapper = getattr(manager, "mapper", None)
            table = getattr(mapper, "local_table", None)
            if mapper is not None and isinstance(table, Table):
                mapped.append((mapper.class_, table))
    return mapped


@event.listens_for(Mapper, "instrument_class")
def _apply_patterns_on_instrument(mapper, class_):  # noqa: ARG001 - event signature
    """Replay every recorded pattern against each newly mapped class.

    ``instrument_class`` fires as the class is defined, which is when the rest
    of pgalchemy registers too. The alternatives -- ``mapper_configured``,
    ``__declare_last__``, ``after_configured`` -- only fire once
    ``configure_mappers()`` runs, which Alembic's autogenerate never does, so
    they would silently register nothing.
    """
    table = mapper.local_table
    if not isinstance(table, Table):
        return
    for pattern in list(registry.patterns):
        pattern.apply_to(class_, table)
