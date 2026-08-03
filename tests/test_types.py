"""Annotation -> PostgreSQL type translation."""
from __future__ import annotations

import uuid
from datetime import date, datetime, time
from decimal import Decimal
from typing import Optional, Union

import pytest
import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

from pgalchemy.types import ReturnTypedExpression, format_type, sql_type_of


@pytest.mark.parametrize(
    "annotation,expected",
    [
        (str, "text"),
        (bool, "boolean"),
        (int, "bigint"),
        (float, "double precision"),
        (Decimal, "decimal"),
        (datetime, "timestamp"),
        (date, "date"),
        (time, "time"),
        (uuid.UUID, "uuid"),
        (bytes, "bytea"),
        (None, "void"),
        (type(None), "void"),
    ],
)
def test_python_primitives(annotation, expected):
    assert format_type(annotation) == expected


@pytest.mark.parametrize(
    "annotation,expected",
    [
        (sqlalchemy.Integer, "integer"),
        (sqlalchemy.BigInteger, "bigint"),
        (sqlalchemy.SmallInteger, "smallint"),
        (sqlalchemy.Text, "text"),
        (sqlalchemy.Boolean, "boolean"),
        (sqlalchemy.DateTime, "timestamp"),
        (sqlalchemy.UUID, "uuid"),
        (sqlalchemy.dialects.postgresql.JSONB, "JSONB"),
    ],
)
def test_sqlalchemy_type_classes(annotation, expected):
    assert format_type(annotation) == expected


def test_sqlalchemy_type_instances_are_formatted_by_their_class():
    assert format_type(sqlalchemy.String(255)) == "varchar"
    assert format_type(sqlalchemy.Integer()) == "integer"


def test_unmapped_sqlalchemy_subclasses_fall_back_to_their_base():
    class MyText(sqlalchemy.Text):
        pass

    assert format_type(MyText) == "text"


@pytest.mark.parametrize(
    "annotation",
    [Optional[int], Union[int, None], int | None],
)
def test_optional_types_are_nullable(annotation):
    assert format_type(annotation) == "bigint null"


def test_unions_of_two_real_types_are_rejected():
    with pytest.raises(ValueError, match="Union types"):
        format_type(Union[int, str])


def test_list_of_a_primitive_is_set_returning():
    assert format_type(list[int]) == "SETOF bigint"


def test_declarative_model_becomes_a_returns_table_clause():
    Base = declarative_base()

    class Row(Base):
        __tablename__ = "rows"
        id = Column(Integer, primary_key=True)
        label = Column(String(20), nullable=False)

    assert format_type(Row) == "TABLE(id integer, label varchar)"


def test_list_of_a_model_does_not_double_wrap():
    Base = declarative_base()

    class Row(Base):
        __tablename__ = "list_rows"
        id = Column(Integer, primary_key=True)

    assert format_type(list[Row]) == "TABLE(id integer)"


def test_plain_annotated_class_uses_its_annotations():
    class Pair:
        left: int
        right: str

    assert format_type(Pair) == "TABLE(left bigint, right text)"


def test_return_typed_expression_annotation_unwraps_its_argument():
    assert format_type(ReturnTypedExpression[int]) == "bigint"


def test_return_typed_expression_instance_knows_its_own_type():
    wrapped = ReturnTypedExpression[str]("select 1")

    assert wrapped.return_type is str
    assert wrapped.get_sql_type() == "text"
    assert sql_type_of(wrapped) == "text"


def test_unparameterised_return_typed_expression_is_rejected():
    with pytest.raises(ValueError, match="parameterised"):
        format_type(ReturnTypedExpression)


def test_unsupported_annotations_raise_a_helpful_error():
    with pytest.raises(ValueError, match="Invalid type annotation"):
        format_type(object())


def test_unresolved_string_annotations_are_reported_clearly():
    with pytest.raises(ValueError, match="Could not resolve the annotation"):
        format_type("SomeModel")
