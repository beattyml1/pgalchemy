import re
from typing import Optional, Union, Any, Type

from sqlalchemy.dialects.postgresql import DOMAIN
from sqlalchemy import BinaryExpression, CheckConstraint, TypeDecorator
from sqlalchemy.sql.base import elements
from sqlalchemy.sql.type_api import TypeEngine, UserDefinedType


class RegexValidatedTextDomainDomain(DOMAIN):
    def __init__(self, name: str, data_type: Union[Type["TypeEngine[Any]"], "TypeEngine[Any]"], *, regex: Union[str, re], collation: Optional[str] = None,
                 default: Union[elements.TextClause, str, None] = None, constraint_name: Optional[str] = None,
                 not_null: Optional[bool] = None,
                 create_type: bool = True, **kw: Any):
        pattern = re.compile(regex).pattern if isinstance(regex, str) else regex.pattern
        check = f"VALUE ~ '{pattern}'"
        super().__init__(name, data_type, collation=collation, default=default, constraint_name=constraint_name,
                         not_null=not_null, check=check, create_type=create_type, **kw)