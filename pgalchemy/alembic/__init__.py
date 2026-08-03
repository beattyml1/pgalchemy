"""Alembic integration for pgalchemy.

Typical ``env.py`` wiring::

    import pgalchemy.alembic.comparator      # RLS + column privilege autogenerate
    from pgalchemy.alembic import register_entities

    register_entities()   # policies, functions and views, via alembic_utils
"""
from __future__ import annotations

from typing import Iterable, List, Optional

from alembic_utils.replaceable_entity import ReplaceableEntity

from ..registry import registry

# Importing the comparator registers the autogenerate comparators and the
# renderers for the operations below, so `import pgalchemy.alembic` is enough
# to wire everything up.
from . import comparator  # noqa: F401  (imported for its side effects)
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


def entities(include_policies: bool = False) -> List:
    """Declared functions and views as ``alembic_utils`` entities.

    Policies are excluded by default: pgalchemy's own comparator handles them,
    which is what lets a policy be created in the same migration as the table
    it protects.
    """
    return registry.entities(include_policies=include_policies)


def managed_entity_types() -> List:
    """The ``alembic_utils`` entity classes pgalchemy hands over."""
    from alembic_utils.pg_function import PGFunction
    from alembic_utils.pg_materialized_view import PGMaterializedView
    from alembic_utils.pg_view import PGView

    return [PGFunction, PGView, PGMaterializedView]


def _set_alembic_utils_scope(entity_types) -> None:
    """Limit which entity types alembic_utils will consider.

    alembic_utils registers a schema-level comparator as soon as it is
    imported, and with an empty registry it emits a drop for every entity it
    finds in the database -- which would revert the policies and column grants
    pgalchemy had just created. pgalchemy imports alembic_utils as an
    implementation detail, so it narrows that scope rather than leaving a
    comparator running that the user never asked for.
    """
    from alembic_utils.replaceable_entity import registry as alembic_utils_registry

    alembic_utils_registry.entity_types = set(entity_types)


class _NoEntities(ReplaceableEntity):
    """Sentinel type that owns nothing, which disables alembic_utils' pass."""

    type_ = "pgalchemy_sentinel"

    @classmethod
    def from_database(cls, sess, schema="%") -> List:
        return []


def allow_alembic_utils_defaults() -> None:
    """Hand full control back to alembic_utils' own comparator.

    Undoes the scoping pgalchemy applies on import. Only needed if you drive
    alembic_utils directly and want it to manage every entity type, including
    the policies pgalchemy also manages.
    """
    from alembic_utils.replaceable_entity import registry as alembic_utils_registry

    alembic_utils_registry.entity_types = set()


def register_entities(
    extra: Optional[Iterable] = None, include_policies: bool = False, **kwargs
) -> List:
    """Hand pgalchemy's functions and views to ``alembic_utils``.

    Call this from ``env.py`` *after* importing the modules that declare your
    models, functions and views. ``extra`` accepts entities you built with
    alembic_utils directly.

    Note that alembic_utils has to reach the live database to work out what a
    function or view means, so on a brand new database the tables they read
    from must be migrated first; a second ``revision --autogenerate`` then
    picks the functions and views up. RLS, policies and column privileges do
    not have this restriction because pgalchemy compares them itself.

    ``entity_types`` defaults to the classes pgalchemy hands over. Left
    unrestricted, alembic_utils treats every entity it finds in the database as
    unmanaged and emits a drop for it -- including the policies and column
    grants that pgalchemy issues itself. Pass ``entity_types=None`` to opt back
    into alembic_utils' default of considering every type.
    """
    from alembic_utils.replaceable_entity import register_entities as _register

    entity_types = kwargs.pop("entity_types", managed_entity_types())
    _set_alembic_utils_scope(entity_types or [_NoEntities])

    all_entities = entities(include_policies=include_policies)
    if extra:
        all_entities.extend(extra)
    _register(all_entities, **kwargs)
    return all_entities


# Applied on import: until the caller opts in with register_entities(),
# alembic_utils' comparator must not undo pgalchemy's own migrations.
_set_alembic_utils_scope([_NoEntities])


__all__ = [
    "ColGrantOp",
    "ColRevokeOp",
    "CreatePolicyOp",
    "DisableRlsOp",
    "DropPolicyOp",
    "EnableRlsOp",
    "ForceRlsOp",
    "NoForceRlsOp",
    "allow_alembic_utils_defaults",
    "entities",
    "managed_entity_types",
    "register_entities",
]
