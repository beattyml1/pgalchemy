"""Reading existing column privileges out of ``information_schema``."""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from sqlalchemy import Connection, Row, text

sql_identifier = str

_SELECT = """
    select grantor, grantee, table_catalog, table_schema, table_name,
           column_name, privilege_type, is_grantable
    from information_schema.column_privileges
"""


class YesOrNo(Enum):
    YES = "YES"
    NO = "NO"


class ColumnPrivilegeType(Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    REFERENCES = "REFERENCES"


class ColumnPrivilege:
    def __init__(
        self,
        grantor: sql_identifier,  # role that granted the privilege
        grantee: sql_identifier,  # role the privilege was granted to
        table_catalog: sql_identifier,  # database containing the table
        table_schema: sql_identifier,  # schema containing the table
        table_name: sql_identifier,  # table containing the column
        column_name: sql_identifier,  # name of the column
        privilege_type: str,  # SELECT, INSERT, UPDATE or REFERENCES
        is_grantable: str,  # YES if the privilege is grantable, NO if not
    ):
        self.is_grantable = is_grantable
        self.privilege_type = privilege_type
        self.column_name = column_name
        self.table_name = table_name
        self.table_schema = table_schema
        self.table_catalog = table_catalog
        self.grantee = grantee
        self.grantor = grantor

    @staticmethod
    def from_row(row: Row) -> "ColumnPrivilege":
        return ColumnPrivilege(**row._asdict())

    @classmethod
    def get_for_table(
        cls, connection: Connection, schema: Optional[str], table_name: str
    ) -> List["ColumnPrivilege"]:
        results = connection.execute(
            text(_SELECT + " where table_name = :table and table_schema = :schema"),
            {"table": table_name, "schema": schema or "public"},
        )
        return [cls.from_row(r) for r in results]

    @classmethod
    def get_for_column(
        cls,
        connection: Connection,
        schema: Optional[str],
        table_name: str,
        column_name: str,
    ) -> List["ColumnPrivilege"]:
        results = connection.execute(
            text(
                _SELECT
                + " where table_name = :table and table_schema = :schema"
                " and column_name = :column"
            ),
            {"table": table_name, "schema": schema or "public", "column": column_name},
        )
        return [cls.from_row(r) for r in results]

    @classmethod
    def get_all(cls, connection: Connection) -> List["ColumnPrivilege"]:
        results = connection.execute(text(_SELECT))
        return [cls.from_row(r) for r in results]

    def is_same(self, privilege_type, grantee) -> bool:
        privilege_type = getattr(privilege_type, "value", privilege_type)
        return str(self.privilege_type) == str(privilege_type) and self.grantee == grantee

    def __repr__(self) -> str:  # pragma: no cover - display only
        return (
            f"ColumnPrivilege({self.privilege_type} on "
            f"{self.table_schema}.{self.table_name}.{self.column_name} to {self.grantee})"
        )
