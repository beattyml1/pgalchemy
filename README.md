# pgalchemy

SQLAlchemy and Alembic support for PostgreSQL features like:

- Row Level Security (RLS)
- Policies
- Column level privileges
- Functions
- Views and materialized views
- Domains

Built on top of `alembic_utils` but with a more usable interface and a few missing features.

## Installation

```shell
pip install pgalchemy
```

OR

```shell
poetry add pgalchemy
```

## Policy and Row Level Security

### Using the RLS BaseModel

Recommended for most projects. This suits projects where the majority of tables use RLS,
which is almost every new project using this library. Models are secure by default, so
forgetting to opt in cannot quietly expose a table.

```python
from sqlalchemy import Column, Integer
from sqlalchemy.orm import declarative_base
from pgalchemy import Policy, PolicyType, PolicyCommands, rls_base

BaseModel = rls_base(declarative_base())

class MyModel(BaseModel):
    __tablename__ = 'my_models'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)

Policy("pol_my_models_select_primary", on=MyModel, as_=PolicyType.PERMISSIVE, for_=PolicyCommands.SELECT, using="user_id = auth.uid()")
Policy("pol_my_models_delete_primary", on=MyModel, as_=PolicyType.PERMISSIVE, for_=PolicyCommands.DELETE, using="user_id = auth.uid()")
Policy("pol_my_models_update_primary", on=MyModel, as_=PolicyType.PERMISSIVE, for_=PolicyCommands.UPDATE, using="user_id = auth.uid()", with_check="user_id = auth.uid()")
Policy("pol_my_models_insert_primary", on=MyModel, as_=PolicyType.PERMISSIVE, for_=PolicyCommands.INSERT, with_check="user_id = auth.uid()")
```

Declaring a `Policy` registers it; there is nothing else to wire up.

### Using the RLS decorator

Only intended for projects where most tables do not have RLS enabled -- usually existing
projects using RLS for a niche use case.

This is not recommended otherwise, as it makes it easy for a developer to forget to enable
RLS and expose a security vulnerability.

```python
from sqlalchemy.orm import declarative_base
from pgalchemy import rls, policy, Policy, PolicyType, PolicyCommands

BaseModel = declarative_base()

@rls()
class MyModel(BaseModel):
    ...

# Equivalent to passing the policies inline:
# @rls(policies=[Policy("pol_my_models_primary", for_=PolicyCommands.ALL, using="user_id = auth.uid()")])
# or, if RLS is already on:
# @policy(Policy("pol_my_models_primary", for_=PolicyCommands.ALL, using="user_id = auth.uid()"))
```

The decorator also works the other way round -- opting a single model out of an
`rls_base`:

```python
@rls(enabled=False)
class PublicSetting(BaseModel):
    ...
```

`@rls(force=True)` additionally emits `ALTER TABLE ... FORCE ROW LEVEL SECURITY`, which
applies policies to the table owner as well.

### Core tables

```python
from pgalchemy.rls import rls_for_table

rls_for_table()(my_table)
```

### Policy options

| argument     | meaning                                                              |
|--------------|----------------------------------------------------------------------|
| `name`       | policy name (first positional argument)                              |
| `on`         | the model or `Table` the policy applies to                           |
| `as_`        | `PolicyType.PERMISSIVE` (default) or `PolicyType.RESTRICTIVE`        |
| `for_`       | `PolicyCommands.ALL` (default), `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| `to`         | role name, or a list of role names                                   |
| `using`      | row visibility expression                                            |
| `with_check` | expression checked on write                                          |

`using` and `with_check` accept either a SQL string or a SQLAlchemy expression;
expressions are compiled with literal binds, so `MyModel.user_id == 1` becomes
`my_models.user_id = 1`.

## Column level security

```python
from sqlalchemy import Column, Boolean
from pgalchemy import allow_for_column, deny_for_column, PolicyCommands

class User(BaseModel):
    __tablename__ = 'users'
    is_admin = allow_for_column(PolicyCommands.SELECT, 'app_reader')(Column(Boolean))
```

pgalchemy only touches role/column combinations you have declared, so grants made outside
of pgalchemy are never silently revoked. Use `manage_cls_for_combo()` to widen what
pgalchemy owns (for example, an entire table for one role).

## Configuration settings

Policies usually need to know who the current user is. PostgreSQL's `set_config` /
`current_setting` are the usual channel, and `pgalchemy.config` wraps them.

```python
from sqlalchemy import Integer, cast, func
from sqlalchemy.orm import Session
from pgalchemy import Policy, PolicyCommands
from pgalchemy.config import configure, config_value

Policy(
    "pol_posts_own",
    on=Post,
    for_=PolicyCommands.ALL,
    using=Post.user_id == cast(func.nullif(config_value("app.user_id"), ""), Integer),
)

with Session(engine) as session:
    configure(session, **{"app.user_id": current_user.id})
    session.scalars(select(Post))    # only that user's posts
```

There is also an attribute-style form, where each attribute builds up the dotted setting
name and the result *is* a SQL expression:

```python
from pgalchemy.config import Config

config = Config(session)
config.app.user_id = 7                             # set_config('app.user_id', '7', true)

Policy("pol_posts_own", on=Post, using=Post.user_id == config.app.user_id)
select(Post).where(Post.user_id == cast(config.app.user_id, Integer))
```

No `.getter()` needed. `Config` inherits SQLAlchemy's `ColumnOperators`, so comparisons
work in both directions and the usual operators are available:

```python
config.app.role == "admin"
config.app.tenant.in_(["acme", "globex"])
config.app.tenant.like("ac%")
cast(config.app.level, Integer) > 3                  # settings are text: cast to compare
cast(func.nullif(config.app.user_id, ""), Integer)
```

Note the cast on the numeric comparison. A setting is always `text`, so `config.app.level > 3`
builds valid-looking SQL that PostgreSQL then rejects with `operator does not exist: text > integer`.
Comparisons against strings need no cast.

`Config()` works without a session, so settings can be referenced at import time when
building policies; only assignment needs one.

By default an unset setting raises rather than reading as `NULL`, so a policy pointing at
a setting nobody populated fails loudly instead of silently matching nothing. Pass
`Config(session, missing_ok=True)` for the opposite; child nodes inherit it.

Because attribute lookup only invents a node for names that aren't real attributes, a
setting segment named like one of the inherited methods (`match`, `like`, `desc`, `op`,
… — see `pgalchemy.config.RESERVED_ATTRIBUTE_NAMES`) can't be spelled with a dot. Call
the node instead:

```python
config.app("match")            # names app.match
config("app.user_id")          # names app.user_id
config.app.set("match", "x")   # assignment equivalent
```

Three things to know:

- **Values are always text.** `current_setting` returns `text` whatever you put in, so
  cast on the way out. Ints, floats, bools, `datetime`, `UUID`, `dict` and `list` are all
  serialised for you (containers as JSON, bools as `true`/`false`).
- **Settings are transaction-local.** `set_config` is called with `is_local=True`, so a
  value is reset at `COMMIT`/`ROLLBACK` and cannot leak into the next transaction that
  borrows the same pooled connection.
- **Custom settings need a dotted prefix.** PostgreSQL rejects `set_config('user_id', ...)`.
  Since a dot is not a valid Python identifier, `configure`'s keyword form only reaches
  built-in settings (`configure(session, statement_timeout='5s')`); for custom ones unpack
  a dict, or use `set_config_value` / `Config`.

Note the `nullif(..., "")` above: once a setting has existed on a connection it is *reset*
rather than removed at the end of a transaction, so it reads back as `''`, and `''::int`
is an error rather than "no user". Guard casts accordingly.

## Functions

### From a Python function

```python
from sqlalchemy import select
from pgalchemy.functions import sql_function
from pgalchemy.types import ReturnTypedExpression

@sql_function(schema='test')
def get_thing(id: int) -> ReturnTypedExpression[MyModel]:
    return ReturnTypedExpression[MyModel](
        select(MyModel).where(MyModel.id == id)
    )
```

The parameter is rendered as a reference to the SQL function's own argument
(`get_thing.id`), not as a Python value, so the generated body is:

```sql
CREATE FUNCTION test.get_thing(id bigint) RETURNS TABLE(id integer, ...) AS $$
SELECT my_models.id, ...
FROM my_models
WHERE my_models.id = get_thing.id
$$ LANGUAGE sql
```

### From a SQL file with an empty Python function

```python
from pgalchemy.functions import sql_function

@sql_function(schema='test', path='../functions/get_thing.sql')
def get_thing(id: int) -> MyModel:
    pass
```

Relative paths resolve against the module that declares the function.

### From a SQL file with explicit metadata

```python
from pgalchemy.functions import Function

Function(
    schema='test',
    path='../functions/get_thing.sql',
    returns=MyModel,
    parameters=[('id', int)],
)
```

`parameters` accepts `(name, type)` tuples, `(name, type, default)` tuples or
`inspect.Parameter` objects.

## Views

### From a Python function

```python
from sqlalchemy import select
from pgalchemy.views import sql_view

@sql_view(schema='test')
def my_view():
    return select(MyModel).where(MyModel.published.is_(True))
```

Pass `materialized=True` for a materialized view.

### From a SQL file

```python
from pgalchemy.views import View

View(schema='test', path='../views/my_view.sql')
```

## Domains

```python
from sqlalchemy import Text
from pgalchemy.domains import RegexValidatedTextDomain

email = RegexValidatedTextDomain('email_address', Text, regex=r'^[^@]+@[^@]+\.[^@]+$')
```

## Alembic setup

In `env.py`:

```python
import pgalchemy.alembic          # registers the comparators and renderers
import myapp.models               # import your models so declarations register

target_metadata = myapp.models.Base.metadata

pgalchemy.alembic.register_entities()   # functions and views, via alembic_utils
```

Then:

```shell
alembic revision --autogenerate -m "..."
alembic upgrade head
```

RLS, policies and column privileges are compared by pgalchemy itself, so they appear in
the same migration as the tables they apply to, and they downgrade cleanly:

```python
def upgrade() -> None:
    op.create_table('users', ...)
    op.enable_rls('users', schema='public')
    op.create_policy('users_select_policy', 'users', 'as PERMISSIVE\nfor SELECT\nusing (true)', schema='public')
    op.grant_column('users', 'SELECT', 'is_admin', 'app_reader', schema='public')
```

### A note on functions and views

`alembic_utils` has to reach the live database to work out what a function or view means.
On a brand new database the tables they read from must therefore exist first: generate and
apply the table migration, then run `revision --autogenerate` again to pick up functions
and views. Policies do not have this restriction.

`register_entities()` also narrows alembic_utils to the entity types pgalchemy hands it.
Without that, alembic_utils treats every entity it finds in the database as unmanaged and
emits a drop for it -- including the policies and column grants pgalchemy just created.
Call `pgalchemy.alembic.allow_alembic_utils_defaults()` if you want its original behaviour.

### Available operations

| operation                                                     | SQL                                          |
|---------------------------------------------------------------|----------------------------------------------|
| `op.enable_rls(table, schema=, force=)`                        | `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`  |
| `op.disable_rls(table, schema=)`                               | `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` |
| `op.force_rls(table, schema=)`                                 | `ALTER TABLE ... FORCE ROW LEVEL SECURITY`   |
| `op.no_force_rls(table, schema=)`                              | `ALTER TABLE ... NO FORCE ROW LEVEL SECURITY`|
| `op.create_policy(name, table, definition, schema=)`           | `CREATE POLICY ...`                          |
| `op.drop_policy(name, table, schema=, definition=)`            | `DROP POLICY ...`                            |
| `op.grant_column(table, privilege, column, role, schema=)`     | `GRANT ... (col) ON ... TO role`             |
| `op.revoke_column(table, privilege, column, role, schema=)`    | `REVOKE ... (col) ON ... FROM role`          |

## Tests

```shell
pytest                  # unit tests; no database required
```

Integration tests need PostgreSQL and skip themselves when none is reachable:

```shell
docker compose up -d
pytest -m integration
```

Point them elsewhere with `PGALCHEMY_TEST_DSN`, e.g.
`PGALCHEMY_TEST_DSN=postgresql+psycopg2://user@localhost:5432/db pytest -m integration`.
