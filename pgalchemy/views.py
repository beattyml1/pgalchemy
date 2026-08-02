"""SQL view declarations, from Python bodies or from .sql files."""
from __future__ import annotations

from typing import Any, Callable, Optional

from alembic_utils.pg_materialized_view import PGMaterializedView
from alembic_utils.pg_view import PGView

from pgalchemy.expressions import (
    _try_get_sql_from_path,
    _try_get_sql_from_returned_expression,
    caller_directory,
)
from pgalchemy.registry import DEFAULT_SCHEMA, registry


def sql_view(
    schema: Optional[str] = None,
    materialized: bool = False,
    name: Optional[str] = None,
    path: Optional[str] = None,
):
    """Declare a view from a Python function returning a ``select()``."""
    base_dir = caller_directory(2)

    def wrapper(func: Callable) -> Callable:
        sql = None if path else _try_get_sql_from_returned_expression(func)
        func.__pgalchemy_view__ = View(
            name=name or func.__name__,
            schema=schema,
            materialized=materialized,
            path=path,
            sql=sql,
            base_dir=base_dir,
        )
        return func

    return wrapper


class View:
    """A PostgreSQL view; registered for autogeneration on construction."""

    def __init__(
        self,
        name: Optional[str] = None,
        schema: Optional[str] = None,
        materialized: bool = False,
        path: Optional[str] = None,
        sql: Optional[str] = None,
        with_data: bool = True,
        base_dir: Optional[Any] = None,
    ):
        if not name and not path:
            raise ValueError("A View needs either a name or a path to derive one from")

        self.name = name or _name_from_path(path)
        self.schema = schema or DEFAULT_SCHEMA
        self.materialized = materialized
        self.with_data = with_data
        self.path = path
        self.sql = sql or _try_get_sql_from_path(path, base_dir)
        if self.sql is None:
            raise ValueError(
                f"View {self.name!r} has no body: return a select() from the decorated "
                f"function, or pass path= / sql="
            )
        registry.register_view(self)

    @property
    def definition_sql(self) -> str:
        return self.sql.strip()

    def create_sql(self) -> str:
        kind = "MATERIALIZED VIEW" if self.materialized else "VIEW"
        return f"CREATE {kind} {self.schema}.{self.name} AS {self.definition_sql}"

    def to_entity(self):
        if self.materialized:
            return PGMaterializedView(
                schema=self.schema,
                signature=self.name,
                definition=self.definition_sql,
                with_data=self.with_data,
            )
        return PGView(
            schema=self.schema,
            signature=self.name,
            definition=self.definition_sql,
        )

    def __repr__(self) -> str:
        kind = "MaterializedView" if self.materialized else "View"
        return f"{kind}({self.schema}.{self.name})"


def _name_from_path(path: str) -> str:
    return path.replace("\\", "/").split("/")[-1].split(".")[0]
