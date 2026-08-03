"""Reading and writing PostgreSQL run-time configuration settings.

PostgreSQL lets you stash arbitrary values in the session with ``set_config``
and read them back with ``current_setting``. That is the usual way to tell a
row level security policy who the current user is::

    Policy(
        "pol_posts_own",
        on=Post,
        using=Post.user_id == cast(config_value("app.user_id"), Integer),
    )

    with Session(engine) as session:
        configure(session, **{"app.user_id": current_user.id})
        session.scalars(select(Post))     # only that user's posts

Three things are worth knowing before using this module:

* **Values are always text.** ``current_setting`` returns ``text`` whatever you
  put in, so cast on the way out (``cast(config_value(...), Integer)``).
* **Settings written here are transaction-local.** ``set_config`` is called
  with ``is_local=True``, so a value lasts until the end of the current
  transaction and is reset by ``COMMIT`` or ``ROLLBACK``. That is what you want
  for request-scoped values like a user id -- it cannot leak into the next
  transaction that borrows the same pooled connection.
* **Custom settings need a dotted prefix.** PostgreSQL rejects
  ``set_config('user_id', ...)`` with *unrecognized configuration parameter*;
  it has to be ``'app.user_id'``. Since a dot is not a valid Python identifier,
  the keyword form of :func:`configure` only reaches built-in settings
  (``configure(session, statement_timeout='5s')``). For custom settings, unpack
  a dict -- ``configure(session, **{"app.user_id": 7})`` -- or use
  :func:`set_config_value` or :class:`Config`.
"""
import json
from datetime import datetime
from typing import Optional, TypeAlias
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.operators import ColumnOperators

#: Python types that can be stored in a PostgreSQL setting. Everything is
#: serialised to text, because that is the only thing a setting can hold.
SqlSerializableType: TypeAlias = str | int | float | bool | dict | datetime | list | UUID

#: Attributes :class:`Config` keeps for itself rather than treating as settings.
_CONFIG_INTERNALS = frozenset({"name", "parent", "_session", "_missing_ok"})


def configure(session: Session, **kwargs: SqlSerializableType) -> None:
    """Set several configuration values on ``session``.

    ``configure(session, statement_timeout='5s')`` for built-in settings;
    ``configure(session, **{"app.user_id": 7})`` for custom ones, which
    PostgreSQL requires to carry a dotted prefix.

    The values apply until the current transaction ends.
    """
    for key, value in kwargs.items():
        set_config_value(session, key, value)


def set_config_value(session: Session, key: str, value: SqlSerializableType) -> None:
    """Set a single configuration value for the rest of the transaction.

    ``key`` must name a built-in setting or a custom one with a dotted prefix,
    e.g. ``'app.user_id'``. ``value`` is serialised to text -- see
    :data:`SqlSerializableType`.
    """
    session.execute(_set_config_value_query(key, value))


def config_value(key: str, missing_ok: bool = True):
    """A ``current_setting(key)`` expression, for use anywhere SQL is built.

    The result is always ``text``; cast it if you need another type. With
    ``missing_ok=True`` (the default) an unset setting reads as ``NULL``; with
    ``missing_ok=False`` PostgreSQL raises *unrecognized configuration
    parameter* instead.

    Note that a setting written in an earlier, now-committed transaction reads
    back as the empty string rather than ``NULL``, because the setting still
    exists on the connection but has been reset.
    """
    return func.current_setting(key, missing_ok)


def _set_config_value_query(key: str, value: SqlSerializableType):
    """``SELECT set_config(key, value, true)`` -- ``true`` meaning transaction-local."""
    return select(func.set_config(key, _serialize(value), True))


def _serialize(value: SqlSerializableType) -> str:
    """Render ``value`` as the text a PostgreSQL setting can hold.

    ``set_config``'s second argument is ``text``; handing PostgreSQL a bind
    parameter of any other type fails with *function set_config(unknown,
    integer, boolean) does not exist*, so every value is converted here.

    Mappings and sequences become JSON, booleans become ``'true'``/``'false'``
    to match PostgreSQL's own rendering, and everything else uses ``str``.
    """
    # bool is a subclass of int, so it has to be tested first.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        return value
    return str(value)


class Config(ColumnOperators):
    """Attribute-style access to configuration settings.

    Each attribute lookup builds up a dotted setting name, so the Python
    spelling matches the PostgreSQL one::

        config = Config(session)
        config.app.user_id = 7          # set_config('app.user_id', '7', true)

    A node *is* a SQL expression, so it drops straight into a query or a policy
    with no ``.getter()`` call::

        Policy("pol_posts_own", on=Post, using=Post.user_id == config.app.user_id)

        select(Post).where(Post.user_id == cast(config.app.user_id, Integer))

    Comparisons work in both directions, and the usual column operators are
    available because this inherits :class:`~sqlalchemy.sql.operators.ColumnOperators`::

        config.app.role == "admin"
        config.app.tenant.in_(["acme", "globex"])
        cast(config.app.level, Integer) > 3
        cast(func.nullif(config.app.user_id, ""), Integer)

    A setting is always ``text``, so comparisons against a number need a cast.
    ``config.app.level > 3`` builds SQL that PostgreSQL then rejects with
    *operator does not exist: text > integer*; comparisons against strings are
    fine as they are.

    A node without a session can still build expressions -- which is what makes
    it usable at import time, where policies are declared. Only assignment
    needs a session.

    **Names that collide with methods.** Attribute lookup only invents a child
    node for names that are not real attributes, so a setting whose segment is
    called ``match``, ``like``, ``desc``, ``op`` and so on (see
    :data:`RESERVED_ATTRIBUTE_NAMES`) cannot be spelled with a dot. Call the
    node instead::

        config.app("match")             # names app.match
        config("app.user_id")           # names app.user_id
    """

    #: SQLAlchemy probes this when coercing an object into an expression: false
    #: means "not a ClauseElement myself, ask __clause_element__". It has to be
    #: a real attribute, because otherwise __getattr__ would answer the probe
    #: with a child node, which is truthy, and SQLAlchemy would conclude this
    #: object is already a clause element and never call __clause_element__.
    is_clause_element = False

    def __init__(
        self,
        session: Session | None = None,
        name: str | None = None,
        parent: Optional["Config"] = None,
        missing_ok: bool | None = None,
    ):
        # These bypass __setattr__ deliberately: that override treats every
        # assignment as a setting write, which would recurse forever here.
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "parent", parent)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_missing_ok", missing_ok)

    # -- building setting names --------------------------------------------
    def __getattr__(self, key: str) -> "Config":
        """Return a child node, so ``config.app.user_id`` names ``app.user_id``.

        Only reached for names that are not real attributes or methods, so
        ``getter``, ``session``, ``in_`` and the rest still resolve normally.

        Underscore-prefixed names are refused rather than invented. Settings do
        not look like that, and libraries probing for private protocol
        attributes must get an ``AttributeError`` instead of a child node --
        a node is truthy, which makes such a probe read as "yes".
        """
        if key.startswith("_"):
            raise AttributeError(key)
        return Config(name=key, parent=self)

    def __call__(self, name: str) -> "Config":
        """Return a child node for a literal name.

        The escape hatch for settings whose names collide with method names,
        and for writing a dotted path in one go: ``config("app.user_id")``.
        """
        return Config(name=name, parent=self)

    def __setattr__(self, key: str, value: SqlSerializableType) -> None:
        """Write ``value`` to the setting this node names, plus ``key``."""
        if key in _CONFIG_INTERNALS:
            object.__setattr__(self, key, value)
            return
        self.set(key, value)

    def set(self, key: str, value: SqlSerializableType) -> None:
        """Write ``value`` to the child setting ``key``, immediately.

        The spelled-out form of ``config.app.user_id = 7``, for names that
        collide with method names.
        """
        session = self.session
        if session is None:
            raise ValueError("Session is required to set config value")
        session.execute(_set_config_value_query(self._child_name(key), value))

    def _child_name(self, key: str) -> str:
        qualified = self._fully_qualified_name()
        return f"{qualified}.{key}" if qualified else key

    def _fully_qualified_name(self) -> str | None:
        """The dotted setting name this node refers to, or ``None`` at the root."""
        if self.parent is None:
            return self.name
        parent_name = self.parent._fully_qualified_name()
        return f"{parent_name}.{self.name}" if parent_name else self.name

    @property
    def session(self) -> Session | None:
        """This node's session, or the nearest ancestor's."""
        if self._session is not None:
            return self._session
        if self.parent is not None:
            return self.parent.session
        return None

    @property
    def missing_ok(self) -> bool:
        """Whether an unset setting reads as ``NULL`` rather than raising.

        Inherited from the nearest ancestor that specified it; ``False`` by
        default, so a policy referring to a setting nobody set fails loudly
        instead of quietly matching nothing.
        """
        if self._missing_ok is not None:
            return self._missing_ok
        if self.parent is not None:
            return self.parent.missing_ok
        return False

    # -- behaving as a SQL expression --------------------------------------
    def __clause_element__(self):
        """Render as ``current_setting(...)`` wherever SQLAlchemy expects SQL.

        This is the hook that lets a node be used without ``.getter()``.
        """
        name = self._fully_qualified_name()
        if name is None:
            raise ValueError(
                "The root Config object does not name a setting. Use an attribute, "
                "e.g. config.app.user_id, or call it: config('app.user_id')."
            )
        return config_value(name, missing_ok=self.missing_ok)

    def operate(self, op, *other, **kwargs):
        return op(self.__clause_element__(), *other, **kwargs)

    def reverse_operate(self, op, other, **kwargs):
        return op(other, self.__clause_element__(), **kwargs)

    def getter(self, missing_ok: bool | None = None):
        """A ``current_setting`` expression for this setting.

        Equivalent to using the node directly; kept for when an explicit
        ``missing_ok`` is wanted for one call.
        """
        if missing_ok is None:
            return self.__clause_element__()
        return config_value(self._fully_qualified_name(), missing_ok=missing_ok)

    def setter(self, value: SqlSerializableType):
        """The ``set_config`` query for this setting, without executing it."""
        return _set_config_value_query(self._fully_qualified_name(), value)

    def __repr__(self) -> str:
        return f"Config({self._fully_qualified_name() or '<root>'})"


#: Method names inherited from SQLAlchemy that attribute lookup cannot shadow.
#: A setting segment named like one of these has to be reached with
#: ``config(...)`` or :meth:`Config.set` instead of a dotted attribute.
RESERVED_ATTRIBUTE_NAMES = frozenset(
    name for name in dir(Config) if not name.startswith("_")
)
