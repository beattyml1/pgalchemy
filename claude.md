# pgalchemy - PostgreSQL RLS and Advanced Features for SQLAlchemy

## Project Overview
pgalchemy is a Python library that extends SQLAlchemy and Alembic with support for advanced PostgreSQL features, particularly Row Level Security (RLS), policies, functions, and views. It provides a more user-friendly interface built on top of alembic_utils.

## Key Technologies
- **Python 3.11+**
- **SQLAlchemy 2.0+** - SQL toolkit and ORM
- **Alembic** - Database migration tool for SQLAlchemy
- **alembic-utils** - Utilities for managing database objects with Alembic
- **PostgreSQL** - Target database with RLS support

## Project Structure
```
pgalchemy/
├── pgalchemy/           # Main package directory
│   ├── __init__.py     # Main exports (rls_base, rls, Policy, etc.)
│   ├── rls.py          # Row Level Security implementation
│   ├── policy.py       # Policy types and definitions
│   ├── functions.py    # SQL function decorators and utilities
│   ├── views.py        # SQL view support
│   ├── types.py        # Type formatting utilities
│   ├── expressions.py  # SQL expression utilities
│   ├── domains.py      # Domain support
│   ├── cls.py          # Column-level security
│   ├── registry.py     # Central registry of every declaration
│   └── alembic/        # Alembic integration
│       ├── comparator.py       # Comparators + renderers for migrations
│       ├── column_privilege.py # Reading column privileges from the DB
│       ├── policy_state.py     # Reading/normalising policies from the DB
│       └── operations/         # Custom Alembic operations
│           ├── rls.py        # RLS enable/disable/force operations
│           ├── policy.py     # Policy create/drop operations
│           └── cls.py        # Column-level security operations
├── tests/              # Test files
├── alembic/           # Alembic configuration (if present)
├── pyproject.toml     # Poetry configuration
└── README.md          # Project documentation
```

## Core Features

### 1. Row Level Security (RLS)
The library provides two approaches for implementing RLS:

**RLS BaseModel (Recommended):**
- For projects with majority of tables using RLS
- Creates a base model with RLS enabled by default
- Use: `BaseModel = rls_base(declarative_base())`

**RLS Decorator:**
- For existing projects with selective RLS usage
- Applied to individual models
- Use: `@rls()` decorator on model classes

### 2. Policies
- Supports PERMISSIVE and RESTRICTIVE policy types
- Commands: SELECT, INSERT, UPDATE, DELETE, ALL
- Policies can use `using` and `with_check` clauses
- Defined using the `Policy` class with table/model reference

### 3. SQL Functions
- Decorator-based function creation: `@sql_function()`
- Support for Python function bodies or SQL files
- Type-safe return types using `ReturnTypedExpression`
- Automatic parameter type inference

### 4. SQL Views
- Similar to functions, supports decorator: `@sql_view()`
- Can use Python expressions or SQL files
- Schema support

### 5. Alembic Integration
- Custom comparators for detecting RLS, policy and column-privilege changes
- Operations for enabling/disabling/forcing RLS
- Operations for creating/dropping policies and column grants
- RLS, policies and column privileges are compared by pgalchemy itself, so they land in
  the same migration as the tables they apply to. Functions and views go through
  `alembic_utils`, which needs the tables to exist first.

## Architecture Notes

- **`pgalchemy/registry.py` is the single source of truth.** RLS flags, policies,
  functions and views all register there, keyed by `(schema, table_name)`. Name keys
  (rather than `Table` identity) are deliberate: `env.py` commonly rebuilds tables into a
  fresh `MetaData` with `to_metadata()`, producing new `Table` objects.

- **Never put non-literal objects in `Table.info`.** Alembic renders `info=` verbatim
  into generated migration scripts, so anything that is not a Python literal produces a
  migration file that will not parse. This is why RLS state lives in the registry.
  `Column.info` is safe -- alembic does not render it -- and is where column privilege
  rules are kept.

- **pgalchemy narrows `alembic_utils` on import.** alembic_utils registers a
  schema-level comparator as soon as it is imported and, with an empty registry, emits a
  drop for every entity it finds in the database -- which would revert pgalchemy's own
  policies and grants. See `pgalchemy/alembic/__init__.py`.

- **Policy change detection round-trips through the database.** PostgreSQL rewrites
  policy expressions when it stores them, so `pgalchemy/alembic/policy_state.py`
  re-creates the declared policy inside a savepoint and compares the two *stored* forms.
  Comparing declared SQL against `pg_policies` text directly produces false positives.

- **Function parameters are qualified with the function name.** PostgreSQL resolves a
  bare identifier that matches a column name in favour of the column, so
  `select(User).where(User.id == id)` renders as `... WHERE users.id = get_user.id`.

## Development Workflow

### Setting Up
```bash
# Install with pip
pip install pgalchemy

# Or with poetry
poetry add pgalchemy
```

### Common Tasks

**Creating a model with RLS:**
```python
from pgalchemy import rls_base, Policy, PolicyType, PolicyCommands

BaseModel = rls_base(declarative_base())

class MyModel(BaseModel):
    # model fields...
    pass

# Add policies
Policy("policy_name", on=MyModel, for_=PolicyCommands.SELECT, using="user_id = auth.uid()")
```

**Running tests:**
```bash
pytest                 # unit tests only; no database required
docker compose up -d   # then, for the integration tests:
pytest -m integration  # skips itself when no PostgreSQL is reachable
```
Override the database with `PGALCHEMY_TEST_DSN`.

**Building the package:**
```bash
poetry build
```

## Important Patterns

1. **RLS is opt-in or opt-out:** Choose between `rls_base` (opt-out) or `@rls` decorator (opt-in) based on project needs

2. **Policy definitions:** Policies are defined separately from models and reference them via the `on` parameter

3. **SQL expressions:** The library supports both Python expressions and raw SQL strings for policies and functions

4. **Type safety:** Uses Python type hints for function parameters and return types

## Dependencies
- Core: sqlalchemy, alembic, alembic-utils
- Dev: pytest, pytest-snapshot

## Version
Current version: 0.1.6 (from pyproject.toml)

## Testing
Tests live in `tests/`. The default suite is pure unit tests with no database. Tests
marked `integration` exercise autogeneration against a real PostgreSQL and skip when none
is reachable.

## Notes for Development
- The library focuses on PostgreSQL-specific features
- Heavy use of SQLAlchemy's event system and metadata
- Alembic operations are extended to support RLS operations
- Type inference and formatting utilities support various SQLAlchemy types