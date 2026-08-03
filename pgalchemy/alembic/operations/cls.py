from alembic.operations import MigrateOperation, Operations


def _qualified(operation) -> str:
    if operation.schema is not None:
        return "%s.%s" % (operation.schema, operation.table_name)
    return operation.table_name


@Operations.register_operation("grant_column")
class ColGrantOp(MigrateOperation):
    """Grant a privilege on a single column to a role."""

    def __init__(self, table_name, operation, column, role, schema=None):
        self.role = role
        self.column = column
        self.operation = operation
        self.table_name = table_name
        self.schema = schema

    @classmethod
    def grant_column(cls, operations, table_name, operation, column, role, **kw):
        """Issue a "GRANT <priv> (<column>) ON <table> TO <role>" instruction."""
        op = ColGrantOp(table_name, operation, column, role, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return ColRevokeOp(
            self.table_name, self.operation, self.column, self.role, schema=self.schema
        )


@Operations.register_operation("revoke_column")
class ColRevokeOp(MigrateOperation):
    """Revoke a privilege on a single column from a role."""

    def __init__(self, table_name, operation, column, role, schema=None):
        self.role = role
        self.column = column
        self.operation = operation
        self.table_name = table_name
        self.schema = schema

    @classmethod
    def revoke_column(cls, operations, table_name, operation, column, role, **kw):
        """Issue a "REVOKE <priv> (<column>) ON <table> FROM <role>" instruction."""
        op = ColRevokeOp(table_name, operation, column, role, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return ColGrantOp(
            self.table_name, self.operation, self.column, self.role, schema=self.schema
        )


def grant_column_sql(operation: ColGrantOp) -> str:
    return "GRANT %s (%s) ON %s TO %s;" % (
        operation.operation,
        operation.column,
        _qualified(operation),
        operation.role,
    )


def revoke_column_sql(operation: ColRevokeOp) -> str:
    return "REVOKE %s (%s) ON %s FROM %s;" % (
        operation.operation,
        operation.column,
        _qualified(operation),
        operation.role,
    )


@Operations.implementation_for(ColGrantOp)
def grant_column(operations, operation: ColGrantOp):
    operations.execute(grant_column_sql(operation))


@Operations.implementation_for(ColRevokeOp)
def revoke_column(operations, operation: ColRevokeOp):
    operations.execute(revoke_column_sql(operation))
