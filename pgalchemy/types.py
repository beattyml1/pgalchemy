"""Translation from Python / SQLAlchemy type annotations into PostgreSQL types."""
from __future__ import annotations

import types as _pytypes
import uuid
from datetime import date, datetime, time
from decimal import Decimal
from typing import (
    Any,
    Generic,
    Optional,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

import sqlalchemy
import sqlalchemy.dialects.postgresql
from sqlalchemy import Table
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql.elements import KeyedColumnElement
from sqlalchemy.sql.type_api import TypeEngine

T = TypeVar("T")

#: Direct Python / SQLAlchemy type -> PostgreSQL type name.
PRIMITIVE_TYPES = {
    str: "text",
    bool: "boolean",
    int: "bigint",
    float: "double precision",
    Decimal: "decimal",
    datetime: "timestamp",
    date: "date",
    time: "time",
    uuid.UUID: "uuid",
    bytes: "bytea",
    dict: "jsonb",
    sqlalchemy.Integer: "integer",
    sqlalchemy.Float: "real",
    sqlalchemy.BigInteger: "bigint",
    sqlalchemy.SmallInteger: "smallint",
    sqlalchemy.Double: "double precision",
    sqlalchemy.Numeric: "numeric",
    sqlalchemy.UUID: "uuid",
    sqlalchemy.dialects.postgresql.UUID: "uuid",
    sqlalchemy.DateTime: "timestamp",
    sqlalchemy.Date: "date",
    sqlalchemy.Time: "time",
    sqlalchemy.Interval: "interval",
    sqlalchemy.Boolean: "boolean",
    sqlalchemy.Text: "text",
    sqlalchemy.String: "varchar",
    sqlalchemy.VARCHAR: "varchar",
    sqlalchemy.NVARCHAR: "varchar",
    sqlalchemy.CHAR: "character",
    sqlalchemy.NCHAR: "character",
    sqlalchemy.LargeBinary: "bytea",
    sqlalchemy.JSON: "JSON",
    sqlalchemy.dialects.postgresql.JSONB: "JSONB",
    sqlalchemy.dialects.postgresql.JSON: "JSON",
    sqlalchemy.dialects.postgresql.MONEY: "MONEY",
    sqlalchemy.dialects.postgresql.BIT: "bit",
    sqlalchemy.dialects.postgresql.DATERANGE: "daterange",
    sqlalchemy.dialects.postgresql.INET: "inet",
    None: "void",
    type(None): "void",
}

_UNSUPPORTED_MESSAGE = (
    "Invalid type annotation for SQL function generation: Must be str, bool, int, "
    "float, Decimal, datetime, date, time, uuid.UUID, a SQLAlchemy type, a "
    "declarative model, a list of one of those, or an Optional/Union of one of "
    "those with None"
)


def format_type(annotation: Any) -> str:
    """Render ``annotation`` as the PostgreSQL type it corresponds to."""
    if annotation is None or annotation is type(None):
        return "void"

    if isinstance(annotation, str):
        raise ValueError(
            f"Could not resolve the annotation {annotation!r} to a type. This usually "
            f"means 'from __future__ import annotations' is in effect and the name is "
            f"not importable from the declaring module; pass the type explicitly with "
            f"returns= or parameters=."
        )

    # ReturnTypedExpression[X] carries its payload type as its single argument.
    if get_origin(annotation) is ReturnTypedExpression:
        return format_type(get_args(annotation)[0])
    if annotation is ReturnTypedExpression:
        raise ValueError(
            "ReturnTypedExpression must be parameterised, e.g. ReturnTypedExpression[int]"
        )

    # A TypeEngine *instance* such as String(255) -- format by its class.
    if isinstance(annotation, TypeEngine):
        return format_type(type(annotation))

    if _is_optional(annotation):
        return _format_union_type(annotation)

    origin = get_origin(annotation)
    if origin is Union or origin is _pytypes.UnionType:
        return _format_union_type(annotation)

    if origin in (list, set, tuple, frozenset):
        args = get_args(annotation)
        if not args:
            raise ValueError(_UNSUPPORTED_MESSAGE)
        element = format_type(args[0])
        # A row shape is already set-returning as `TABLE(...)`; there is no
        # such thing as `SETOF TABLE(...)`.
        return element if element.startswith("TABLE(") else f"SETOF {element}"

    if isinstance(annotation, type):
        primitive = _try_format_primitive_type(annotation)
        if primitive is not None:
            return primitive

        table = _table_for(annotation)
        if table is not None:
            return _format_row_shape(table.columns)

        annotations = _class_annotations(annotation)
        if annotations:
            columns = ", ".join(f"{k} {format_type(t)}" for k, t in annotations.items())
            return f"TABLE({columns})"

    if isinstance(annotation, Table):
        return _format_row_shape(annotation.columns)

    raise ValueError(_UNSUPPORTED_MESSAGE)


def _class_annotations(annotation: type) -> dict:
    """Annotations of a plain class, with string forms resolved where possible.

    ``from __future__ import annotations`` leaves ``__annotations__`` holding
    strings, which the formatter cannot map to SQL types.
    """
    try:
        return get_type_hints(annotation)
    except Exception:
        return dict(getattr(annotation, "__annotations__", {}) or {})


def _format_row_shape(columns) -> str:
    """A ``RETURNS TABLE(...)`` clause for a set of columns.

    Nullability is deliberately omitted: PostgreSQL rejects constraints in a
    ``RETURNS TABLE`` column list.
    """
    return "TABLE(" + ", ".join(_format_column(column) for column in columns) + ")"


def _table_for(annotation: type) -> Optional[Table]:
    table = getattr(annotation, "__table__", None)
    if isinstance(table, Table):
        return table
    if issubclass(annotation, DeclarativeBase):  # pragma: no cover - defensive
        return annotation.__table__
    return None


def _is_optional(annotation: Any) -> bool:
    origin = get_origin(annotation)
    if origin is not Union and origin is not _pytypes.UnionType:
        return False
    return type(None) in get_args(annotation)


def _format_column(column: KeyedColumnElement) -> str:
    return f"{column.name} {format_type(column.type)}"


def _format_union_type(annotation: Any) -> str:
    args = get_args(annotation)
    main_args = [a for a in args if a is not None and a is not type(None)]
    if len(args) != 2 or len(main_args) != 1:
        raise ValueError(
            "Invalid type annotation for SQL function generation: Union types must be "
            "a primitive sql compatible type unioned with None"
        )
    return format_type(main_args[0]) + " null"


def _try_format_primitive_type(annotation: type) -> Optional[str]:
    """Look up ``annotation``, falling back to the nearest mapped base class."""
    try:
        return PRIMITIVE_TYPES[annotation]
    except (KeyError, TypeError):
        pass
    for base in getattr(annotation, "__mro__", ())[1:]:
        if base in PRIMITIVE_TYPES:
            return PRIMITIVE_TYPES[base]
    return None


def _format_primitive_type(annotation: Any) -> str:
    """Strict primitive lookup; raises ``KeyError`` for unmapped types."""
    return PRIMITIVE_TYPES[annotation]


class ReturnTypedExpression(Generic[T]):
    """Wraps a SQLAlchemy expression with the SQL type it resolves to.

    A ``select()`` or a boolean expression does not tell us what the enclosing
    SQL function should declare as its ``RETURNS`` type, so the author supplies
    it: ``ReturnTypedExpression[MyModel](select(MyModel))``.
    """

    def __init__(self, expression: Any = None):
        self.expression = expression

    @property
    def return_type(self) -> Any:
        """The ``X`` from ``ReturnTypedExpression[X]``, if it was parameterised."""
        orig_class = getattr(self, "__orig_class__", None)
        if orig_class is not None:
            args = get_args(orig_class)
            if args:
                return args[0]
        return None

    def get_sql_type(self) -> Optional[str]:
        return_type = self.return_type
        return None if return_type is None else format_type(return_type)

    def __repr__(self) -> str:
        return f"ReturnTypedExpression({self.expression!r})"


def sql_type_of(annotation: Any) -> Optional[str]:
    """PostgreSQL type for an annotation or a ``ReturnTypedExpression`` instance."""
    if annotation is None:
        return None
    if isinstance(annotation, ReturnTypedExpression):
        return annotation.get_sql_type()
    return format_type(annotation)
