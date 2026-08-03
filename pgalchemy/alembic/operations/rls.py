from alembic.operations import MigrateOperation, Operations


def _qualified(operation) -> str:
    if operation.schema is not None:
        return "%s.%s" % (operation.schema, operation.table_name)
    return operation.table_name


@Operations.register_operation("enable_rls")
class EnableRlsOp(MigrateOperation):
    """Enable row level security on a table."""

    def __init__(self, table_name, schema=None, force=False):
        self.table_name = table_name
        self.schema = schema
        self.force = force

    @classmethod
    def enable_rls(cls, operations, table_name, **kw):
        """Issue an "ALTER TABLE ... ENABLE ROW LEVEL SECURITY" instruction."""
        op = EnableRlsOp(table_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return DisableRlsOp(self.table_name, schema=self.schema)


@Operations.register_operation("disable_rls")
class DisableRlsOp(MigrateOperation):
    """Disable row level security on a table."""

    def __init__(self, table_name, schema=None):
        self.table_name = table_name
        self.schema = schema

    @classmethod
    def disable_rls(cls, operations, table_name, **kw):
        """Issue an "ALTER TABLE ... DISABLE ROW LEVEL SECURITY" instruction."""
        op = DisableRlsOp(table_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return EnableRlsOp(self.table_name, schema=self.schema)


@Operations.register_operation("force_rls")
class ForceRlsOp(MigrateOperation):
    """Apply row level security to the table owner as well."""

    def __init__(self, table_name, schema=None):
        self.table_name = table_name
        self.schema = schema

    @classmethod
    def force_rls(cls, operations, table_name, **kw):
        op = ForceRlsOp(table_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        return NoForceRlsOp(self.table_name, schema=self.schema)


@Operations.register_operation("no_force_rls")
class NoForceRlsOp(MigrateOperation):
    """Stop applying row level security to the table owner."""

    def __init__(self, table_name, schema=None):
        self.table_name = table_name
        self.schema = schema

    @classmethod
    def no_force_rls(cls, operations, table_name, **kw):
        op = NoForceRlsOp(table_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        return ForceRlsOp(self.table_name, schema=self.schema)


def enable_rls_sql(operation: EnableRlsOp) -> str:
    return "ALTER TABLE %s ENABLE ROW LEVEL SECURITY;" % _qualified(operation)


def disable_rls_sql(operation: DisableRlsOp) -> str:
    return "ALTER TABLE %s DISABLE ROW LEVEL SECURITY;" % _qualified(operation)


def force_rls_sql(operation: ForceRlsOp) -> str:
    return "ALTER TABLE %s FORCE ROW LEVEL SECURITY;" % _qualified(operation)


def no_force_rls_sql(operation: NoForceRlsOp) -> str:
    return "ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;" % _qualified(operation)


@Operations.implementation_for(EnableRlsOp)
def enable_rls(operations, operation: EnableRlsOp):
    operations.execute(enable_rls_sql(operation))
    if operation.force:
        operations.execute(force_rls_sql(operation))


@Operations.implementation_for(DisableRlsOp)
def disable_rls(operations, operation: DisableRlsOp):
    operations.execute(disable_rls_sql(operation))


@Operations.implementation_for(ForceRlsOp)
def force_rls(operations, operation: ForceRlsOp):
    operations.execute(force_rls_sql(operation))


@Operations.implementation_for(NoForceRlsOp)
def no_force_rls(operations, operation: NoForceRlsOp):
    operations.execute(no_force_rls_sql(operation))
