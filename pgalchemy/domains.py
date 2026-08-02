"""PostgreSQL DOMAIN helpers."""
from __future__ import annotations

import re
from typing import Any, Optional, Union

from sqlalchemy.dialects.postgresql import DOMAIN
from sqlalchemy.sql import elements
from sqlalchemy.sql.type_api import TypeEngine

#: A plain domain is just SQLAlchemy's DOMAIN; re-exported for discoverability.
Domain = DOMAIN


class RegexValidatedTextDomain(DOMAIN):
    """A DOMAIN whose CHECK constraint is generated from a regular expression.

    ``RegexValidatedTextDomain('email', Text, regex=r'^[^@]+@[^@]+$')`` produces
    ``CHECK (VALUE ~ '^[^@]+@[^@]+$')``.
    """

    def __init__(
        self,
        name: str,
        data_type: Union[type, "TypeEngine[Any]"],
        *,
        regex: Union[str, "re.Pattern[str]"],
        collation: Optional[str] = None,
        default: Union[elements.TextClause, str, None] = None,
        constraint_name: Optional[str] = None,
        not_null: Optional[bool] = None,
        create_type: bool = True,
        **kw: Any,
    ):
        pattern = regex.pattern if isinstance(regex, re.Pattern) else re.compile(regex).pattern
        self.regex = pattern
        escaped = pattern.replace("'", "''")
        check = f"VALUE ~ '{escaped}'"
        super().__init__(
            name,
            data_type,
            collation=collation,
            default=default,
            constraint_name=constraint_name,
            not_null=not_null,
            check=check,
            create_type=create_type,
            **kw,
        )


#: Retained for compatibility with the original (double-suffixed) class name.
RegexValidatedTextDomainDomain = RegexValidatedTextDomain
