# pgalchemy

SQLAlchemy and Alembic support for PostgreSQL features like:

- Row Level Security (RLS)
- Policies
- Column level privileges
- Schema control policies -- project-wide guardrails over all of the above
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

## Schema control policies

Everything above describes permissioning one table at a time. A **schema control policy**
is the guardrail over all of it, modelled on AWS's Service Control Policies: a `Policy` is
the IAM policy, granting access on one specific resource; a schema control policy is the
SCP, attaching to a container (schema ≈ OU), governing every resource inside it
(table ≈ account), and never granting anything -- its only power is to refuse.

```python
from pgalchemy import schema_control_policy, ControlledTable, evaluate_control_policies

@schema_control_policy(on="public")
def rls_required(table: ControlledTable):
    if not table.rls_enabled:
        yield "row level security is not enabled"

def test_schema_is_compliant():
    evaluate_control_policies(Base.metadata).raise_for_status()
```

`on` names the schema(s) governed; omit it to govern every schema. The body is handed a
`ControlledTable` and signals compliance by yielding nothing. Declaring a control policy
registers it, so importing the module that defines one is all the wiring there is.

### What a control policy receives

`ControlledTable` gathers everything pgalchemy knows about one table -- RLS flags and
policies from the registry, column privileges from `Column.info` -- into one object.

| attribute | |
|-----------|--|
| `table`, `model`, `schema`, `name`, `qualified_name` | identity; `schema` is always spelled out, never `None` |
| `rls`, `rls_enabled`, `rls_forced` | declared RLS state |
| `rls_declared` | tells "explicitly off" apart from "never considered" |
| `policies` | every `Policy` on the table |
| `policies_for(command)` | policies covering one command, with `ALL` expanded |
| `commands_covered` | commands some *permissive* policy grants |
| `columns`, `column(name)`, `has_column(name)` | `ControlledColumn` per column, each with `.rules`, `.grants`, `.revocations`, `.roles` |
| `roles` | every role named anywhere on the table |
| `indexed(*columns)` | whether an index leads with those columns |

A body may yield a string, or a `Violation` to set a severity or name a column:

```python
from pgalchemy import Violation, Severity

@schema_control_policy(on=["public", "app"])
def tenant_columns_are_indexed(table: ControlledTable):
    if table.has_column("tenant_id") and not table.indexed("tenant_id"):
        yield Violation("tenant_id is not indexed",
                        severity=Severity.WARNING, column="tenant_id")
```

`Severity.ERROR` (the default) fails `raise_for_status()`; `Severity.WARNING` is reported
through `warnings` and leaves the report passing.

### Exempting a table

Either on the policy, for exceptions known where it is written:

```python
@schema_control_policy(on="public", exempt=[Country, "public.alembic_version"])
def rls_required(table): ...
```

or on the model, for exceptions that belong next to the table:

```python
from pgalchemy import schema_control_exception

@schema_control_exception(rls_required, reason="public reference data, no tenant column")
class Country(BaseModel):
    __tablename__ = 'countries'
```

`reason` is required, and is carried into the report rather than quietly removing the
table from the results. Pass `All.All` to exempt from every control policy. For Core
tables, call it: `schema_control_exception(rls_required, reason="...")(my_table)`.

### Reviewing what is not enforced

`security_review()` returns the standing inventory of every deliberate deviation that does
*not* fail the build -- exemptions and warnings -- as plain data, ready to snapshot. Errors
are absent by design: they abort the run, so they can never be a state anybody has to
review.

```python
import yaml
from pgalchemy import security_review

def test_security_exceptions_are_reviewed(snapshot):
    snapshot.assert_match(
        yaml.safe_dump(security_review(Base.metadata), sort_keys=False),
        "security_review.yaml",
    )
```

Any change to what the project excuses then shows up as a diff on that file, which is the
thing a security team reviews:

```yaml
control_policies:
- name: rls_required
  schemas: [public]
- name: tenant_columns_are_indexed
  schemas: [public]
exemptions:
- table: public.alembic_version
  policy: rls_required
  reason: null
  source: policy
- table: public.countries
  policy: rls_required
  reason: public reference data, no tenant column
  source: model
warnings:
- table: public.documents
  column: tenant_id
  policy: tenant_columns_are_indexed
  message: tenant_id is not indexed
```

`source` is `model` for an exemption declared with `@schema_control_exception`, which
always carries a `reason`, and `policy` for one listed in `exempt=`, which has no reason
to give. Because it is data rather than prose, a team can enforce its own standard
directly:

```python
def test_every_exemption_says_why():
    review = security_review(Base.metadata)
    assert [e for e in review["exemptions"] if not e["reason"]] == []
```

`control_policies` lists the policies that ran. It matters more than it looks: deleting a
control policy silently removes every exemption against it, and without the roster that
diff reads as risk going down rather than a check being taken away. Everything is sorted
and nothing is padded, so a diff shows only what actually changed. Use `json.dumps` if you
prefer JSON; the structure is plain `str`/`list`/`dict`/`None` either way.

### Built-in control policies

```python
from pgalchemy.control_policies import (
    use_recommended, rls_required, writes_require_with_check,
)

use_recommended(on="public")                                           # all of them
use_recommended(rls_required, writes_require_with_check, on="public")  # or pick
```

| policy | catches |
|--------|---------|
| `rls_required` | a table with no `ENABLE ROW LEVEL SECURITY` |
| `policies_require_rls` | policies declared on a table with RLS off -- they are never consulted |
| `every_command_has_a_policy` | RLS on with a command left uncovered, which denies it outright |
| `writes_require_with_check` | an `UPDATE` policy with `using` but no `with_check`, or an `INSERT` policy with no `with_check` at all |
| `no_unconditional_using` | a permissive policy of `using (true)`, which overrides every other policy |
| `column_privileges_are_valid` | `GRANT DELETE (col)` -- not a column privilege in PostgreSQL |

`use_recommended(..., severity=Severity.WARNING)` downgrades the whole set, which is how
to introduce these to a codebase that does not pass yet: every failure is still printed,
but the report stays green.

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

### Enforcing control policies

`register_entities(control_policies=True)` makes `revision --autogenerate` evaluate every
declared schema control policy and abort on a violation, so a schema that fails its own
guardrails never reaches a migration file:

```shell
$ alembic revision --autogenerate -m "add documents"
SchemaControlViolation: 1 violation

  public.documents  rls_required  row level security is not enabled
```

It is off by default -- a comparator that can refuse to generate anything should be asked
for explicitly. No database is consulted, so it behaves identically in offline `--sql`
mode.

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
