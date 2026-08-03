"""Helpers for turning Python/SQLAlchemy expressions and .sql files into SQL text."""
from __future__ import annotations

import inspect
import os
import pathlib
from typing import Any, Optional, Tuple

from sqlalchemy import literal_column
from sqlalchemy.sql.elements import ClauseElement

from pgalchemy.types import ReturnTypedExpression

_PACKAGE_DIR = pathlib.Path(__file__).parent.resolve()

SQL_SUFFIXES = (".sql", ".psql")


def render_expression(expression: Any) -> Optional[str]:
    """Render ``expression`` as PostgreSQL text.

    Strings pass through untouched so hand written SQL stays verbatim.
    SQLAlchemy constructs are compiled against the PostgreSQL dialect with
    literal binds so the result is standalone SQL rather than ``:param``
    placeholders that a migration could not execute.
    """
    if expression is None:
        return None
    if isinstance(expression, str):
        return expression
    if isinstance(expression, ReturnTypedExpression):
        return render_expression(expression.expression)
    if isinstance(expression, ClauseElement):
        from sqlalchemy.dialects import postgresql

        compiled = expression.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
        return str(compiled).strip()
    return str(expression)


def caller_directory(stack_offset: int = 1) -> pathlib.Path:
    """Directory of the first stack frame outside of pgalchemy itself.

    Relative ``path=`` arguments are resolved against the file that declared
    the function or view, which is what a caller writing
    ``'../functions/get_thing.sql'`` expects.
    """
    for frame_info in inspect.stack()[stack_offset:]:
        filename = frame_info.filename
        if not filename or filename.startswith("<"):
            continue
        try:
            directory = pathlib.Path(filename).parent.resolve()
        except OSError:  # pragma: no cover - defensive
            continue
        if directory != _PACKAGE_DIR and _PACKAGE_DIR not in directory.parents:
            return directory
    return pathlib.Path.cwd()  # pragma: no cover - defensive


def _try_get_sql_from_path(
    path: Optional[str], base_dir: Optional[os.PathLike] = None
) -> Optional[str]:
    """Read SQL from ``path``, resolved relative to ``base_dir`` when relative."""
    if not path:
        return None

    if not path.endswith(SQL_SUFFIXES):
        raise ValueError(
            f"Path parameter must be a path to a {' or '.join(SQL_SUFFIXES)} file, got {path!r}"
        )

    candidate = pathlib.Path(path)
    if candidate.is_absolute():
        full_path = candidate
    else:
        base = pathlib.Path(base_dir) if base_dir is not None else caller_directory(2)
        full_path = pathlib.Path(os.path.normpath(base / candidate))

    try:
        return full_path.read_text()
    except FileNotFoundError:
        raise ValueError(f"File {full_path} does not exist") from None


def parameter_placeholders(func, qualifier: Optional[str] = None) -> Tuple[Any, ...]:
    """Build stand-in arguments so a decorated function can be called for its SQL.

    Each parameter becomes a SQL identifier of the same name, so a body like
    ``select(User).where(User.id == id)`` renders as ``... WHERE users.id =
    get_user.id`` -- a reference to the SQL function's own argument rather than
    to a Python value.

    ``qualifier`` should be the SQL function's name. PostgreSQL resolves a bare
    identifier that matches a column name in favour of the column, so
    qualifying with the function name is what keeps ``id`` meaning "the
    argument" rather than "the column".
    """
    signature = inspect.signature(func)
    return tuple(
        literal_column(f"{qualifier}.{name}" if qualifier else name)
        for name, parameter in signature.parameters.items()
        if parameter.kind
        not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    )


def _try_get_sql_from_returned_expression(func, qualifier: Optional[str] = None) -> Optional[str]:
    """Render whatever expression ``func`` returns, or ``None`` if it returns nothing.

    Functions that only carry a signature -- their body is ``pass`` and the SQL
    comes from ``path=`` -- return ``None``, which callers treat as "look
    elsewhere for the SQL".
    """
    result = func(*parameter_placeholders(func, qualifier))
    return render_expression(result)
