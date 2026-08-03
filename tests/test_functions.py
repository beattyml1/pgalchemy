"""SQL function declaration from Python bodies and from .sql files."""
import inspect

import pytest
from sqlalchemy import Column, Integer, String, func, select
from sqlalchemy.orm import declarative_base

from pgalchemy import ReturnTypedExpression, sql_function
from pgalchemy.functions import Function, parameter
from pgalchemy.registry import registry


@pytest.fixture()
def Model():
    Base = declarative_base()

    class Item(Base):
        __tablename__ = "items"
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)
        label = Column(String(50), nullable=False)

    return Item


def test_decorator_returns_the_original_function():
    @sql_function()
    def noop() -> int:
        return ReturnTypedExpression[int](select(1))

    assert callable(noop)
    assert noop.__name__ == "noop"


def test_decorator_registers_the_function():
    @sql_function(schema="app")
    def total() -> int:
        return ReturnTypedExpression[int](select(1))

    declared = total.__pgalchemy_function__
    assert declared in registry.functions
    assert declared.schema == "app"
    assert declared.name == "total"


def test_signature_and_return_type_come_from_the_annotations(Model):
    @sql_function(schema="public")
    def item_count(owner_id: int) -> int:
        return ReturnTypedExpression[int](
            select(func.count(Model.id)).where(Model.owner_id == owner_id)
        )

    declared = item_count.__pgalchemy_function__
    assert declared.signature == "item_count(owner_id bigint)"
    assert declared.returns_sql == "bigint"


def test_parameters_are_qualified_with_the_function_name(Model):
    """PostgreSQL resolves a bare ``owner_id`` to the *column*, not the argument."""

    @sql_function(schema="public")
    def items_for(owner_id: int) -> ReturnTypedExpression[int]:
        return ReturnTypedExpression[int](
            select(Model.id).where(Model.owner_id == owner_id)
        )

    body = items_for.__pgalchemy_function__.body
    assert "items_for.owner_id" in body


def test_return_type_can_be_inferred_from_the_returned_wrapper(Model):
    @sql_function(schema="public")
    def labels():
        return ReturnTypedExpression[str](select(Model.label))

    assert labels.__pgalchemy_function__.returns_sql == "text"


def test_a_bare_expression_without_a_type_is_rejected(Model):
    with pytest.raises(ValueError, match="ReturnTypedExpression"):

        @sql_function(schema="public")
        def untyped():
            return select(Model.id)


def test_generated_sql_is_a_complete_create_function_statement(Model):
    @sql_function(schema="public")
    def one() -> int:
        return ReturnTypedExpression[int](select(1))

    sql = one.__pgalchemy_function__.create_sql()
    assert sql.startswith("CREATE FUNCTION public.one() RETURNS bigint AS $$")
    assert sql.rstrip().endswith("$$ LANGUAGE sql")


def test_defaults_are_rendered_into_the_signature():
    declared = Function(
        name="greet",
        parameters=[parameter("name", str, "world"), parameter("loud", bool, False)],
        returns=str,
        sql="SELECT 1",
    )

    assert declared.signature == "greet(name text default 'world', loud boolean default false)"


def test_a_falsy_default_is_still_a_default():
    """``if arg.default:`` would silently drop ``0``, ``False`` and ``''``."""
    declared = Function(
        name="zero", parameters=[parameter("n", int, 0)], returns=int, sql="SELECT 1"
    )

    assert "default 0" in declared.signature


def test_parameters_without_defaults_have_none_rendered():
    declared = Function(
        name="plain", parameters=[parameter("n", int)], returns=int, sql="SELECT 1"
    )

    assert declared.signature == "plain(n bigint)"


def test_parameters_accept_inspect_parameter_and_tuples():
    from_inspect = Function(
        name="a",
        parameters=[
            inspect.Parameter("n", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=int)
        ],
        returns=int,
        sql="SELECT 1",
    )
    from_tuple = Function(name="b", parameters=[("n", int)], returns=int, sql="SELECT 1")

    assert from_inspect.signature == "a(n bigint)"
    assert from_tuple.signature == "b(n bigint)"


def test_a_function_needs_a_body():
    with pytest.raises(ValueError, match="no body"):
        Function(name="empty", returns=int)


def test_a_function_needs_a_name_or_a_path():
    with pytest.raises(ValueError, match="name or a path"):
        Function(sql="SELECT 1", returns=int)


def test_to_entity_produces_an_alembic_utils_function():
    declared = Function(name="e", parameters=[("n", int)], returns=int, sql="SELECT n")
    entity = declared.to_entity()

    assert entity.schema == "public"
    assert entity.signature == "e(n bigint)"
    assert entity.definition.lower().startswith("returns bigint")


class TestSqlFiles:
    def test_sql_is_read_relative_to_the_declaring_module(self, tmp_path, monkeypatch):
        sql_dir = tmp_path / "sql"
        sql_dir.mkdir()
        (sql_dir / "get_thing.sql").write_text("RETURN 1;")

        declared = Function(
            path="sql/get_thing.sql",
            parameters=[("id", int)],
            returns=int,
            schema="public",
            base_dir=tmp_path,
        )

        assert declared.name == "get_thing"
        assert "RETURN 1;" in declared.body
        assert declared.language == "plpgsql"

    def test_a_plpgsql_body_is_wrapped_in_a_block(self, tmp_path):
        (tmp_path / "f.sql").write_text("RETURN 1;")
        declared = Function(path="f.sql", returns=int, base_dir=tmp_path)

        assert declared.body == "BEGIN\nRETURN 1;\nEND;"

    def test_an_existing_block_is_left_alone(self, tmp_path):
        (tmp_path / "g.sql").write_text("DECLARE x int;\nBEGIN\nRETURN 1;\nEND;")
        declared = Function(path="g.sql", returns=int, base_dir=tmp_path)

        assert declared.body.count("BEGIN") == 1

    def test_a_missing_file_is_reported(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            Function(path="nope.sql", returns=int, base_dir=tmp_path)

    def test_non_sql_paths_are_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"\.sql or \.psql"):
            Function(path="thing.txt", returns=int, base_dir=tmp_path)
