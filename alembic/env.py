import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# This alembic environment exists to exercise pgalchemy against the demo models
# in tests/. A real project would point target_metadata at its own models.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importing pgalchemy.alembic registers the RLS / column-privilege comparators
# and the renderers for the operations they emit.
import pgalchemy.alembic  # noqa: E402
from tests.models import demo  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

if os.environ.get("PGALCHEMY_TEST_DSN"):
    config.set_main_option("sqlalchemy.url", os.environ["PGALCHEMY_TEST_DSN"])

target_metadata = demo.metadata

# RLS, policies and column privileges are compared by pgalchemy itself, so they
# are generated in the same migration as the tables they apply to.
#
# Functions and views go through alembic_utils, which has to reach the live
# database to work out what they mean. On a brand new database the tables they
# read from must therefore be migrated first, so this second pass is opt-in:
#
#     alembic revision --autogenerate -m "tables"      # tables, RLS, policies
#     alembic upgrade head
#     PGALCHEMY_REGISTER_ENTITIES=1 \
#         alembic revision --autogenerate -m "functions and views"
#     alembic upgrade head
if os.environ.get("PGALCHEMY_REGISTER_ENTITIES"):
    pgalchemy.alembic.register_entities()


def run_migrations_offline() -> None:
    """Run migrations without a DBAPI connection ("--sql" mode)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
