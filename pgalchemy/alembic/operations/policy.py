from alembic.operations import MigrateOperation, Operations


def _qualified(operation) -> str:
    if operation.schema is not None:
        return "%s.%s" % (operation.schema, operation.table_name)
    return operation.table_name


@Operations.register_operation("create_policy")
class CreatePolicyOp(MigrateOperation):
    """Create a row level security policy on a table."""

    def __init__(self, policy_name, table_name, definition, schema=None):
        self.policy_name = policy_name
        self.table_name = table_name
        self.definition = definition
        self.schema = schema

    @classmethod
    def create_policy(cls, operations, policy_name, table_name, definition, **kw):
        """Issue a "CREATE POLICY" instruction."""
        op = CreatePolicyOp(policy_name, table_name, definition, **kw)
        return operations.invoke(op)

    def reverse(self):
        return DropPolicyOp(
            self.policy_name, self.table_name, schema=self.schema, definition=self.definition
        )


@Operations.register_operation("drop_policy")
class DropPolicyOp(MigrateOperation):
    """Drop a row level security policy from a table."""

    def __init__(self, policy_name, table_name, schema=None, definition=None):
        self.policy_name = policy_name
        self.table_name = table_name
        self.schema = schema
        # Kept only so that a drop can be reversed into the matching create.
        self.definition = definition

    @classmethod
    def drop_policy(cls, operations, policy_name, table_name, **kw):
        """Issue a "DROP POLICY" instruction."""
        op = DropPolicyOp(policy_name, table_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        if self.definition is None:
            raise NotImplementedError(
                f"Cannot reverse the drop of policy {self.policy_name!r}: its definition "
                f"was not captured."
            )
        return CreatePolicyOp(
            self.policy_name, self.table_name, self.definition, schema=self.schema
        )


def create_policy_sql(operation: CreatePolicyOp) -> str:
    return "CREATE POLICY %s ON %s %s;" % (
        operation.policy_name,
        _qualified(operation),
        operation.definition,
    )


def drop_policy_sql(operation: DropPolicyOp) -> str:
    return "DROP POLICY %s ON %s;" % (operation.policy_name, _qualified(operation))


@Operations.implementation_for(CreatePolicyOp)
def create_policy(operations, operation: CreatePolicyOp):
    operations.execute(create_policy_sql(operation))


@Operations.implementation_for(DropPolicyOp)
def drop_policy(operations, operation: DropPolicyOp):
    operations.execute(drop_policy_sql(operation))
