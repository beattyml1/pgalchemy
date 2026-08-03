"""Shared fixtures.

The unit tests in this package never touch a database. Anything that needs a
live PostgreSQL is marked ``integration`` and skips itself when one is not
reachable, so ``pytest`` passes on a bare checkout.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text

from pgalchemy import cls as cls_module
from pgalchemy.registry import registry

DEFAULT_DSN = "postgresql+psycopg2://testuser:testpass@localhost:5432/testdb"


def test_dsn() -> str:
    """DSN for the integration database (``docker compose up -d`` provides it)."""
    return os.environ.get("PGALCHEMY_TEST_DSN", DEFAULT_DSN)


@pytest.fixture(autouse=True)
def isolate_registry():
    """Restore the global registries after every test.

    pgalchemy registers declarations at import time by design, so tests that
    declare models must not leak into their neighbours.
    """
    saved_rls = dict(registry.rls)
    saved_policies = {key: dict(value) for key, value in registry.policies.items()}
    saved_functions = list(registry.functions)
    saved_views = list(registry.views)
    saved_patterns = list(registry.patterns)
    saved_combos = list(cls_module._cls_registry)

    yield registry

    registry.rls.clear()
    registry.rls.update(saved_rls)
    registry.policies.clear()
    registry.policies.update(saved_policies)
    registry.functions[:] = saved_functions
    registry.views[:] = saved_views
    registry.patterns[:] = saved_patterns
    cls_module._cls_registry[:] = saved_combos


@pytest.fixture(scope="session")
def pg_engine():
    """A live PostgreSQL engine, or a skip when none is reachable."""
    dsn = test_dsn()
    try:
        engine = create_engine(dsn)
        with engine.connect() as connection:
            connection.execute(text("select 1"))
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"PostgreSQL is not available at {dsn}: {exc}")
    return engine


@pytest.fixture()
def pg_connection(pg_engine):
    """A connection whose work is rolled back at the end of the test."""
    with pg_engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()
