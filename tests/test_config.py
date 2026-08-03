"""PostgreSQL run-time configuration settings (set_config / current_setting).

The unit tests here check serialisation and the SQL that gets built; the
``integration`` ones at the bottom check that PostgreSQL actually accepts it and
gives the value back.
"""
import json
import uuid
from datetime import datetime

import pytest
from sqlalchemy import Column, Integer, cast, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, declarative_base

from pgalchemy.config import (
    Config,
    _serialize,
    _set_config_value_query,
    config_value,
    configure,
    set_config_value,
)

UUID_VALUE = uuid.UUID("12345678-1234-5678-1234-567812345678")

_Base = declarative_base()


class Post(_Base):
    """A stand-in table for the expression tests."""

    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)


def sql(expression) -> str:
    return str(
        expression.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


class TestSerialize:
    """``set_config``'s second argument is ``text``.

    Handing PostgreSQL a bind parameter of any other type fails with
    *function set_config(unknown, integer, boolean) does not exist*, so every
    supported type has to come out of here as a string.
    """

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("hello", "hello"),
            ("", ""),
            (42, "42"),
            (0, "0"),
            (-1, "-1"),
            (3.14, "3.14"),
            (datetime(2026, 1, 2, 3, 4, 5), "2026-01-02 03:04:05"),
            (UUID_VALUE, "12345678-1234-5678-1234-567812345678"),
        ],
    )
    def test_scalars_become_text(self, value, expected):
        assert _serialize(value) == expected

    @pytest.mark.parametrize("value,expected", [(True, "true"), (False, "false")])
    def test_booleans_use_postgres_spelling(self, value, expected):
        assert _serialize(value) == expected

    def test_booleans_are_not_treated_as_integers(self):
        """``bool`` subclasses ``int``, so the order of the checks matters."""
        assert _serialize(True) != "1"

    @pytest.mark.parametrize(
        "value", [{"a": 1}, {"nested": {"b": [1, 2]}}, [1, 2, 3], [], {}]
    )
    def test_containers_become_json(self, value):
        assert json.loads(_serialize(value)) == value

    def test_every_supported_type_serialises_to_a_string(self):
        for value in [
            "s",
            1,
            1.5,
            True,
            {"a": 1},
            [1],
            datetime(2026, 1, 1),
            UUID_VALUE,
        ]:
            assert isinstance(_serialize(value), str), value

    def test_subclasses_are_handled_by_their_base_type(self):
        class MyDict(dict):
            pass

        assert json.loads(_serialize(MyDict(a=1))) == {"a": 1}


class TestQueryConstruction:
    def test_set_config_is_transaction_local(self):
        """``is_local=True`` keeps a value from leaking into the next transaction."""
        assert sql(_set_config_value_query("app.user_id", 7)) == (
            "SELECT set_config('app.user_id', '7', true) AS set_config_1"
        )

    def test_the_value_is_passed_as_text(self):
        assert "'7'" in sql(_set_config_value_query("app.user_id", 7))

    def test_config_value_defaults_to_missing_ok(self):
        assert sql(select(config_value("app.user_id"))) == (
            "SELECT current_setting('app.user_id', true) AS current_setting_1"
        )

    def test_config_value_can_require_the_setting(self):
        assert "'app.user_id', false" in sql(select(config_value("app.user_id", False)))

    def test_config_value_composes_into_a_policy_expression(self):
        """The reason this module exists: telling a policy who the user is."""
        expression = Post.user_id == cast(config_value("app.user_id"), Integer)

        assert sql(expression) == (
            "posts.user_id = CAST(current_setting('app.user_id', true) AS INTEGER)"
        )


class FakeSession:
    """Records what would have been executed."""

    def __init__(self):
        self.executed = []

    def execute(self, statement):
        self.executed.append(sql(statement))
        return None


class TestConfigure:
    def test_set_config_value_executes_against_the_session(self):
        session = FakeSession()

        set_config_value(session, "app.user_id", 7)

        assert session.executed == [
            "SELECT set_config('app.user_id', '7', true) AS set_config_1"
        ]

    def test_configure_sets_every_keyword(self):
        session = FakeSession()

        configure(session, statement_timeout="5s", lock_timeout="1s")

        assert len(session.executed) == 2
        assert any("statement_timeout" in stmt for stmt in session.executed)
        assert any("lock_timeout" in stmt for stmt in session.executed)

    def test_configure_accepts_dotted_names_by_dict_unpacking(self):
        """Custom settings need a dotted prefix, which is not a Python identifier."""
        session = FakeSession()

        configure(session, **{"app.user_id": 7, "app.tenant": "acme"})

        assert any("'app.user_id', '7'" in stmt for stmt in session.executed)
        assert any("'app.tenant', 'acme'" in stmt for stmt in session.executed)

    def test_configure_with_no_arguments_does_nothing(self):
        session = FakeSession()

        configure(session)

        assert session.executed == []


class TestConfigObject:
    def test_a_root_config_can_be_constructed(self):
        """``__setattr__`` is overridden, so ``__init__`` must bypass it."""
        assert Config()._fully_qualified_name() is None

    def test_attribute_access_builds_a_dotted_name(self):
        assert Config().app.user_id._fully_qualified_name() == "app.user_id"

    def test_names_nest_to_any_depth(self):
        assert Config().a.b.c.d._fully_qualified_name() == "a.b.c.d"

    def test_a_single_attribute_is_the_whole_name(self):
        assert Config().statement_timeout._fully_qualified_name() == "statement_timeout"

    def test_assignment_writes_the_fully_qualified_setting(self):
        session = FakeSession()

        Config(session).app.user_id = 7

        assert session.executed == [
            "SELECT set_config('app.user_id', '7', true) AS set_config_1"
        ]

    def test_assignment_at_the_root_uses_the_bare_name(self):
        session = FakeSession()

        Config(session).statement_timeout = "5s"

        assert "set_config('statement_timeout', '5s', true)" in session.executed[0]

    def test_assignment_serialises_like_the_functional_api(self):
        session = FakeSession()

        Config(session).app.flag = True

        assert "'true'" in session.executed[0]

    def test_getter_requires_the_setting_by_default(self):
        assert sql(select(Config().app.user_id.getter())) == (
            "SELECT current_setting('app.user_id', false) AS current_setting_1"
        )

    def test_getter_can_tolerate_a_missing_setting(self):
        assert "'app.user_id', true" in sql(
            select(Config().app.user_id.getter(missing_ok=True))
        )

    def test_a_child_can_be_named_explicitly_by_calling_the_node(self):
        assert Config().app("user_id")._fully_qualified_name() == "app.user_id"

    def test_calling_the_root_accepts_a_whole_dotted_path(self):
        assert Config()("app.user_id")._fully_qualified_name() == "app.user_id"

    def test_set_writes_a_child_by_literal_name(self):
        session = FakeSession()

        Config(session).app.set("user_id", 7)

        assert "set_config('app.user_id', '7', true)" in session.executed[0]

    def test_setter_builds_the_query_without_executing_it(self):
        session = FakeSession()

        statement = Config(session).app.user_id.setter(7)

        assert session.executed == []
        assert "set_config('app.user_id', '7', true)" in sql(statement)

    def test_expressions_can_be_built_without_a_session(self):
        """Settings are referenced at import time, long before a session exists."""
        assert "app.user_id" in sql(select(Config().app.user_id.getter()))

    def test_assignment_without_a_session_is_refused(self):
        with pytest.raises(ValueError, match="Session is required"):
            Config().app.user_id = 7

    def test_child_nodes_inherit_the_session_from_their_root(self):
        session = FakeSession()

        assert Config(session).a.b.c.session is session

    def test_real_attributes_are_not_shadowed_by_name_building(self):
        config = Config(name="app")

        assert config.name == "app"
        assert config.parent is None
        assert callable(config.getter)

    def test_underscore_names_are_refused_so_protocol_probes_get_an_error(self):
        """A child node is truthy, so inventing one answers "yes" to any probe."""
        config = Config().app

        with pytest.raises(AttributeError):
            config.__deepcopy__
        with pytest.raises(AttributeError):
            config._private

        assert repr(config) == "Config(app)"
        assert repr(Config()) == "Config(<root>)"


class TestConfigAsExpression:
    """A node is usable directly in SQL, with no ``.getter()`` call."""

    def test_a_node_renders_as_current_setting(self):
        assert sql(select(Config().app.user_id)) == (
            "SELECT current_setting('app.user_id', false) AS current_setting_1"
        )

    def test_a_column_compared_to_a_node(self):
        assert sql(Post.user_id == Config().app.user_id) == (
            "posts.user_id = current_setting('app.user_id', false)"
        )

    def test_a_node_compared_to_a_value(self):
        """Needs ColumnOperators; plain ``__eq__`` would return a bool."""
        assert sql(Config().app.role == "admin") == (
            "current_setting('app.role', false) = 'admin'"
        )

    @pytest.mark.parametrize(
        "build,expected",
        [
            (lambda c: c.app.level > 3, "current_setting('app.level', false) > 3"),
            (lambda c: c.app.level < 3, "current_setting('app.level', false) < 3"),
            (lambda c: c.app.level >= 3, "current_setting('app.level', false) >= 3"),
            (lambda c: c.app.level <= 3, "current_setting('app.level', false) <= 3"),
            (
                lambda c: c.app.role != "admin",
                "current_setting('app.role', false) != 'admin'",
            ),
        ],
    )
    def test_comparison_operators(self, build, expected):
        """Rendering only. A setting is text, so the numeric ones need a cast
        before PostgreSQL will accept them -- see the integration tests."""
        assert sql(build(Config())) == expected

    def test_a_numeric_comparison_needs_an_explicit_cast(self):
        assert sql(cast(Config().app.level, Integer) > 3) == (
            "CAST(current_setting('app.level', false) AS INTEGER) > 3"
        )

    @pytest.mark.parametrize(
        "build,expected",
        [
            (
                lambda c: c.app.tenant.in_(["acme", "globex"]),
                "current_setting('app.tenant', false) IN ('acme', 'globex')",
            ),
            (
                lambda c: c.app.tenant.is_(None),
                "current_setting('app.tenant', false) IS NULL",
            ),
            (
                lambda c: c.app.tenant.like("ac%"),
                "current_setting('app.tenant', false) LIKE 'ac%%'",
            ),
        ],
    )
    def test_column_operator_methods(self, build, expected):
        assert sql(build(Config())) == expected

    def test_a_node_can_be_cast(self):
        assert sql(cast(Config().app.user_id, Integer)) == (
            "CAST(current_setting('app.user_id', false) AS INTEGER)"
        )

    def test_a_node_can_be_passed_to_a_sql_function(self):
        from sqlalchemy import func

        assert sql(cast(func.nullif(Config().app.user_id, ""), Integer)) == (
            "CAST(nullif(current_setting('app.user_id', false), '') AS INTEGER)"
        )

    def test_a_node_works_in_where_and_order_by(self):
        statement = (
            select(Post.id)
            .where(Post.user_id == cast(Config().app.user_id, Integer))
            .order_by(Config().app.user_id)
        )

        rendered = sql(statement)
        assert "WHERE posts.user_id = CAST(current_setting('app.user_id', false)" in rendered
        assert "ORDER BY current_setting('app.user_id', false)" in rendered

    def test_a_node_drops_into_a_policy(self):
        from pgalchemy import Policy, PolicyCommands

        declared = Policy(
            "pol_posts_own",
            on=Post,
            for_=PolicyCommands.ALL,
            using=Post.user_id == cast(Config().app.user_id, Integer),
        )

        assert (
            "using (posts.user_id = "
            "CAST(current_setting('app.user_id', false) AS INTEGER))"
        ) in declared.definition_sql()

    def test_the_root_node_is_not_a_valid_expression(self):
        with pytest.raises(ValueError, match="does not name a setting"):
            select(Config())

    def test_nodes_stay_hashable(self):
        """Defining __eq__ would otherwise make them unhashable."""
        assert isinstance(hash(Config().app.user_id), int)

    def test_is_clause_element_is_a_real_attribute(self):
        """The probe SQLAlchemy uses; a child node here would be truthy."""
        assert Config().app.is_clause_element is False

    def test_missing_ok_defaults_to_strict(self):
        assert "'app.user_id', false" in sql(select(Config().app.user_id))

    def test_missing_ok_can_be_set_on_the_root_and_is_inherited(self):
        assert "'app.user_id', true" in sql(select(Config(missing_ok=True).app.user_id))
        assert Config(missing_ok=True).a.b.c.missing_ok is True

    def test_reserved_names_are_reported(self):
        from pgalchemy.config import RESERVED_ATTRIBUTE_NAMES

        assert {"in_", "like", "getter", "session"} <= RESERVED_ATTRIBUTE_NAMES

    def test_a_reserved_name_is_reachable_by_calling_the_node(self):
        """``config.app.match`` would return the method, so call instead."""
        assert callable(Config().app.match)
        assert sql(select(Config().app("match"))) == (
            "SELECT current_setting('app.match', false) AS current_setting_1"
        )


@pytest.mark.integration
class TestAgainstPostgres:
    """Every declared type must survive a real round trip."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("hello", "hello"),
            (42, "42"),
            (3.14, "3.14"),
            (True, "true"),
            (False, "false"),
            ({"a": 1}, '{"a": 1}'),
            ([1, 2], "[1, 2]"),
            (datetime(2026, 1, 2, 3, 4, 5), "2026-01-02 03:04:05"),
            (UUID_VALUE, "12345678-1234-5678-1234-567812345678"),
        ],
    )
    def test_values_round_trip(self, pg_engine, value, expected):
        with Session(pg_engine) as session:
            set_config_value(session, "app.probe", value)

            assert session.execute(select(config_value("app.probe"))).scalar() == expected

    def test_an_integer_setting_can_be_cast_back(self, pg_engine):
        with Session(pg_engine) as session:
            set_config_value(session, "app.user_id", 7)
            typed = session.execute(
                select(cast(config_value("app.user_id"), Integer))
            ).scalar()

            assert typed == 7

    def test_an_unset_setting_reads_as_null(self, pg_engine):
        with Session(pg_engine) as session:
            assert session.execute(select(config_value("app.never_set"))).scalar() is None

    def test_an_unset_setting_raises_when_not_missing_ok(self, pg_engine):
        from sqlalchemy.exc import ProgrammingError

        with Session(pg_engine) as session:
            with pytest.raises(ProgrammingError, match="unrecognized configuration"):
                session.execute(select(config_value("app.never_set", False))).scalar()

    def test_settings_do_not_survive_the_transaction(self, pg_engine):
        """``is_local=True`` is what stops a value leaking across pooled connections."""
        with Session(pg_engine) as session:
            set_config_value(session, "app.user_id", 7)
            assert session.execute(select(config_value("app.user_id"))).scalar() == "7"

            session.commit()

            assert session.execute(select(config_value("app.user_id"))).scalar() != "7"

    def test_a_reset_setting_reads_as_empty_string_not_null(self, pg_engine):
        """Worth knowing: ``''::int`` is an error, so cast through NULLIF.

        Once a setting has been created on a connection it keeps existing after
        the transaction that set it ends -- it is merely reset -- so it comes
        back as ``''`` rather than ``NULL``.
        """
        with Session(pg_engine) as session:
            set_config_value(session, "app.user_id", 7)
            session.commit()

            assert session.execute(select(config_value("app.user_id"))).scalar() == ""

    def test_casting_a_reset_setting_needs_nullif(self, pg_engine):
        """``NULLIF(setting, '')`` is the idiom a policy should use."""
        from sqlalchemy import func
        from sqlalchemy.exc import DataError

        with Session(pg_engine) as session:
            set_config_value(session, "app.user_id", 7)
            session.commit()

            with pytest.raises(DataError, match="invalid input syntax"):
                session.execute(select(cast(config_value("app.user_id"), Integer))).scalar()
            session.rollback()

            guarded = cast(func.nullif(config_value("app.user_id"), ""), Integer)
            assert session.execute(select(guarded)).scalar() is None

    def test_a_custom_setting_must_have_a_dotted_prefix(self, pg_engine):
        """Why configure()'s keyword form only reaches built-in settings."""
        from sqlalchemy.exc import ProgrammingError

        with Session(pg_engine) as session:
            with pytest.raises(ProgrammingError, match="unrecognized configuration"):
                set_config_value(session, "user_id", 7)

    def test_a_builtin_setting_works_as_a_keyword(self, pg_engine):
        with Session(pg_engine) as session:
            configure(session, statement_timeout="5s")

            assert (
                session.execute(select(config_value("statement_timeout"))).scalar() == "5s"
            )

    def test_config_object_round_trips(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            config.app.user_id = 7

            assert session.execute(select(config.app.user_id.getter())).scalar() == "7"

    def test_a_node_is_queryable_without_getter(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            config.app.user_id = 7

            assert session.execute(select(config.app.user_id)).scalar() == "7"

    def test_a_node_compares_against_a_value_in_the_database(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            config.app.role = "admin"

            assert session.execute(select(config.app.role == "admin")).scalar() is True
            assert session.execute(select(config.app.role == "guest")).scalar() is False

    def test_a_node_casts_in_the_database(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            config.app.user_id = 7

            assert session.execute(select(cast(config.app.user_id, Integer))).scalar() == 7

    def test_string_operators_need_no_cast(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            config.app.tenant = "acme"

            assert session.execute(
                select(config.app.tenant.in_(["acme", "globex"]))
            ).scalar() is True
            assert session.execute(select(config.app.tenant.like("ac%"))).scalar() is True

    def test_comparing_a_setting_to_a_number_requires_a_cast(self, pg_engine):
        """A setting is always text; ``text > integer`` is not an operator."""
        from sqlalchemy.exc import ProgrammingError

        with Session(pg_engine) as session:
            config = Config(session)
            config.app.level = 5

            with pytest.raises(ProgrammingError, match="operator does not exist"):
                session.execute(select(config.app.level > 3)).scalar()
            session.rollback()

            config.app.level = 5
            assert (
                session.execute(select(cast(config.app.level, Integer) > 3)).scalar()
                is True
            )

    def test_a_strict_node_raises_on_an_unset_setting(self, pg_engine):
        from sqlalchemy.exc import ProgrammingError

        with Session(pg_engine) as session:
            with pytest.raises(ProgrammingError, match="unrecognized configuration"):
                session.execute(select(Config().app.never_set_at_all)).scalar()

    def test_a_missing_ok_node_reads_null_for_an_unset_setting(self, pg_engine):
        with Session(pg_engine) as session:
            node = Config(missing_ok=True).app.also_never_set
            assert session.execute(select(node)).scalar() is None

    def test_config_setter_query_round_trips(self, pg_engine):
        with Session(pg_engine) as session:
            config = Config(session)
            session.execute(config.app.tenant.setter("acme"))

            assert session.execute(select(config.app.tenant.getter())).scalar() == "acme"

    @pytest.mark.parametrize(
        "user_id,expected", [(100, [1]), (200, [2]), (999, []), (None, [])]
    )
    def test_a_setting_drives_a_row_level_security_policy(
        self, pg_engine, user_id, expected
    ):
        """The end-to-end reason the module exists.

        The query runs as an unprivileged role: superusers and table owners
        bypass row level security, so a check made as the connecting user would
        pass no matter what the policy said.
        """
        from sqlalchemy import text

        with pg_engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text("CREATE TABLE cfg_posts (id int primary key, user_id int)")
                )
                connection.execute(text("INSERT INTO cfg_posts VALUES (1, 100), (2, 200)"))
                connection.execute(text("ALTER TABLE cfg_posts ENABLE ROW LEVEL SECURITY"))
                connection.execute(
                    text(
                        "CREATE POLICY pol_own ON cfg_posts USING "
                        # NULLIF, not a bare cast: a setting left over from a
                        # finished transaction reads back as '', and ''::int
                        # is an error rather than "no user".
                        "(user_id = NULLIF(current_setting('app.user_id', true), '')::int)"
                    )
                )
                connection.execute(text("CREATE ROLE cfg_reader"))
                connection.execute(text("GRANT SELECT ON cfg_posts TO cfg_reader"))

                if user_id is not None:
                    connection.execute(_set_config_value_query("app.user_id", user_id))
                connection.execute(text("SET LOCAL ROLE cfg_reader"))

                visible = (
                    connection.execute(text("SELECT id FROM cfg_posts ORDER BY id"))
                    .scalars()
                    .all()
                )

                assert visible == expected
            finally:
                transaction.rollback()
