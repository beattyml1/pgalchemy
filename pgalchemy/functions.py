"""SQL function declarations, from Python bodies or from .sql files."""
from __future__ import annotations

import inspect
from typing import Any, Callable, Iterable, Optional, Sequence, get_args, get_origin

from alembic_utils.pg_function import PGFunction

from pgalchemy.expressions import (
    _try_get_sql_from_path,
    _try_get_sql_from_returned_expression,
    caller_directory,
)
from pgalchemy.registry import DEFAULT_SCHEMA, registry
from pgalchemy.types import ReturnTypedExpression, format_type

EMPTY = inspect.Parameter.empty


def parameter(name: str, annotation: Any, default: Any = EMPTY) -> inspect.Parameter:
    """Convenience factory for a positional SQL function parameter."""
    return inspect.Parameter(
        name, inspect.Parameter.POSITIONAL_OR_KEYWORD, default=default, annotation=annotation
    )


def sql_function(
    path: Optional[str] = None,
    schema: Optional[str] = None,
    name: Optional[str] = None,
    language: Optional[str] = None,
    returns: Any = None,
):
    """Declare a SQL function from a Python function.

    The body comes either from the expression the function returns or, when
    ``path`` is given, from a ``.sql``/``.psql`` file next to the declaring
    module. The ``RETURNS`` type is taken from the return annotation, or from a
    returned :class:`~pgalchemy.types.ReturnTypedExpression`.
    """
    base_dir = caller_directory(2)

    def wrapper(func: Callable) -> Callable:
        function_name = name or func.__name__
        sql = None if path else _try_get_sql_from_returned_expression(func, function_name)
        func.__pgalchemy_function__ = Function(
            name=function_name,
            parameters=params(func),
            returns=returns if returns is not None else _return_type_for(func),
            path=path,
            sql=sql,
            schema=schema,
            language=language,
            base_dir=base_dir,
        )
        return func

    return wrapper


class Function:
    """A PostgreSQL function; registered for autogeneration on construction."""

    def __init__(
        self,
        name: Optional[str] = None,
        parameters: Iterable[Any] = (),
        returns: Any = None,
        path: Optional[str] = None,
        sql: Optional[str] = None,
        schema: Optional[str] = None,
        language: Optional[str] = None,
        base_dir: Optional[Any] = None,
    ):
        if not name and not path:
            raise ValueError("A Function needs either a name or a path to derive one from")

        self.name = name or _name_from_path(path)
        self.schema = schema or DEFAULT_SCHEMA
        self.parameters: Sequence[inspect.Parameter] = [
            _coerce_parameter(p) for p in parameters or ()
        ]
        self.returns = returns
        self.path = path
        self.sql = sql or _try_get_sql_from_path(path, base_dir)
        if self.sql is None:
            raise ValueError(
                f"Function {self.name!r} has no body: return a SQL expression from the "
                f"decorated function, or pass path= / sql="
            )
        # A single rendered query is valid `language sql`; a hand written file
        # is far more likely to be a plpgsql block.
        self.language = language or ("plpgsql" if path else "sql")
        registry.register_function(self)

    @property
    def signature(self) -> str:
        args = ", ".join(_format_arg(arg) for arg in self.parameters)
        return f"{self.name}({args})"

    @property
    def returns_sql(self) -> str:
        return returns_for_type(self.returns) or "void"

    @property
    def body(self) -> str:
        sql = self.sql.strip()
        if self.language == "plpgsql" and "begin" not in sql.lower():
            return f"BEGIN\n{sql}\nEND;"
        return sql

    def definition_sql(self) -> str:
        """Everything after ``CREATE FUNCTION schema.signature``."""
        return (
            f"RETURNS {self.returns_sql} AS $$\n"
            f"{self.body}\n"
            f"$$ LANGUAGE {self.language}"
        )

    def create_sql(self) -> str:
        return f"CREATE FUNCTION {self.schema}.{self.signature} {self.definition_sql()}"

    def to_entity(self) -> PGFunction:
        return PGFunction(
            schema=self.schema,
            signature=self.signature,
            definition=self.definition_sql(),
        )

    def __repr__(self) -> str:
        return f"Function({self.schema}.{self.signature})"


def _name_from_path(path: str) -> str:
    return path.replace("\\", "/").split("/")[-1].split(".")[0]


def _coerce_parameter(value: Any) -> inspect.Parameter:
    """Accept ``inspect.Parameter``, ``(name, type)`` or ``(name, type, default)``."""
    if isinstance(value, inspect.Parameter):
        return value
    if isinstance(value, dict):
        return parameter(**value)
    if isinstance(value, (tuple, list)) and len(value) in (2, 3):
        return parameter(*value)
    raise TypeError(
        f"Cannot interpret {value!r} as a function parameter. Use inspect.Parameter, "
        f"a (name, type) tuple or a (name, type, default) tuple."
    )


def _format_arg(arg: inspect.Parameter) -> str:
    main = f"{arg.name} {format_type(arg.annotation)}"
    if arg.default is EMPTY:
        return main
    return f"{main} default {_format_default(arg.default)}"


def _format_default(default: Any) -> str:
    if default is None:
        return "null"
    if isinstance(default, bool):
        return "true" if default else "false"
    if isinstance(default, str):
        escaped = default.replace("'", "''")
        return f"'{escaped}'"
    return str(default)


def resolved_signature(func: Callable) -> inspect.Signature:
    """``inspect.signature`` with string annotations evaluated where possible.

    ``from __future__ import annotations`` turns every annotation into a
    string; without this the type formatter would be handed ``'int'`` instead
    of ``int``. Annotations that reference names not visible from the
    function's module are left as strings and reported by the formatter.
    """
    try:
        return inspect.signature(func, eval_str=True)
    except (NameError, TypeError, AttributeError):
        return inspect.signature(func)


def params(func: Callable) -> Sequence[inspect.Parameter]:
    signature = resolved_signature(func)
    return [
        p
        for p in signature.parameters.values()
        if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]


def returns_for_type(annotation: Any) -> Optional[str]:
    if annotation is None:
        return None
    if get_origin(annotation) is ReturnTypedExpression:
        return format_type(get_args(annotation)[0])
    if isinstance(annotation, ReturnTypedExpression):
        return annotation.get_sql_type()
    return format_type(annotation)


def _return_type_for(func: Callable) -> Any:
    return _return_type_from_annotation(func) or _return_type_from_result(func)


def _return_type_from_annotation(func: Callable) -> Any:
    annotation = resolved_signature(func).return_annotation
    if annotation is inspect.Signature.empty:
        return None
    return annotation


def _return_type_from_result(func: Callable) -> Any:
    """Infer the return type by calling the function and inspecting the result."""
    from pgalchemy.expressions import parameter_placeholders
    from sqlalchemy.sql.elements import ClauseElement

    result = func(*parameter_placeholders(func))
    if isinstance(result, ReturnTypedExpression):
        return result.return_type
    if isinstance(result, ClauseElement):
        raise ValueError(
            "Please wrap your returned expression with a ReturnTypedExpression() so "
            "that we have type information to generate your function"
        )
    return None
