"""The control policies pgalchemy ships with.

Each one encodes a mistake that is easy to make, invisible in review, and only
discovered in production. Nothing here is active on import -- declaring a
control policy registers it, so these are built lazily by :func:`use_recommended`
and only for the schemas you name::

    from pgalchemy.control_policies import use_recommended

    use_recommended(on="public")

Pick individual ones by passing their builders::

    use_recommended(rls_required, writes_require_with_check, on="public")

They are builders rather than ready-made policies precisely because attachment
is per-schema: the same check usually wants declaring against whichever schemas
a given project actually uses.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, List, Optional, Union

from .policy import PolicyCommands, PolicyType
from .schema_control import (
    CONCRETE_COMMANDS,
    ControlledTable,
    SchemaControlPolicy,
    Severity,
    Violation,
    schema_control_policy,
)

#: Expressions that make a ``using`` clause a no-op. PostgreSQL stores the
#: literal it was given, so the declared text is what is compared here.
_UNCONDITIONAL = frozenset({"true", "(true)", "1=1", "(1=1)"})

#: The privileges PostgreSQL actually accepts on a single column. Notably
#: ``DELETE`` is not among them -- it is a table-level privilege only, because
#: a row is deleted whole.
#:
#: Spelled out rather than read from
#: :class:`~pgalchemy.alembic.column_privilege.ColumnPrivilegeType`, which would
#: drag the whole Alembic subpackage -- and its alembic_utils side effects --
#: into a module that only ever needs four strings.
_COLUMN_PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def rls_required(**kwargs) -> SchemaControlPolicy:
    """Every table must have row level security enabled."""

    @schema_control_policy(name="rls_required", **kwargs)
    def check(table: ControlledTable):
        if not table.rls_enabled:
            if table.rls_declared:
                yield "row level security is declared but switched off"
            else:
                yield "row level security is not enabled"

    return check


def policies_require_rls(**kwargs) -> SchemaControlPolicy:
    """A table with policies must have RLS on, or the policies do nothing.

    This is the quietest failure in the whole library. ``CREATE POLICY``
    succeeds against a table without ``ENABLE ROW LEVEL SECURITY``, and the
    policy is simply never consulted -- so the table reads as protected, the
    migration applies cleanly, and every row is visible to everyone.
    """

    @schema_control_policy(name="policies_require_rls", **kwargs)
    def check(table: ControlledTable):
        if table.policies and not table.rls_enabled:
            names = sorted(policy.name for policy in table.policies)
            if len(names) == 1:
                yield (
                    f"policy {names[0]!r} is declared but row level security is not "
                    f"enabled, so it is never consulted"
                )
            else:
                yield (
                    f"{len(names)} policies are declared ({', '.join(names)}) but row "
                    f"level security is not enabled, so none of them is ever consulted"
                )

    return check


def every_command_has_a_policy(**kwargs) -> SchemaControlPolicy:
    """With RLS on, every command needs a permissive policy or it is denied.

    RLS denies by default. A table that enables it and then declares only a
    ``SELECT`` policy has silently become append-nothing, update-nothing and
    delete-nothing, which usually surfaces as a mystifying "0 rows affected".
    """

    @schema_control_policy(name="every_command_has_a_policy", **kwargs)
    def check(table: ControlledTable):
        if not table.rls_enabled:
            return
        missing = [
            command for command in CONCRETE_COMMANDS
            if command not in table.commands_covered
        ]
        if missing:
            yield (
                f"row level security is on but no permissive policy covers "
                f"{', '.join(str(command) for command in missing)}, so those commands "
                f"are denied outright"
            )

    return check


def writes_require_with_check(**kwargs) -> SchemaControlPolicy:
    """An ``UPDATE`` policy needs ``with_check``, not just ``using``.

    ``using`` decides which rows a caller may update *from*; ``with_check``
    decides what they may update them *into*. Given only ``using``, a caller can
    take a row they own and rewrite its owner to someone else -- handing the row
    away, or quietly stealing one, depending which way round you read it.

    ``INSERT`` is checked too. It honours only ``with_check``, so an ``INSERT``
    policy expressed with ``using`` constrains nothing at all.
    """

    @schema_control_policy(name="writes_require_with_check", **kwargs)
    def check(table: ControlledTable):
        for policy in table.policies_for(PolicyCommands.UPDATE):
            if policy.as_ is PolicyType.RESTRICTIVE:
                continue
            if policy.using and not policy.with_check:
                yield (
                    f"policy {policy.name!r} covers UPDATE with using but no "
                    f"with_check, so a caller can update a row out of their own set"
                )
        for policy in table.policies_for(PolicyCommands.INSERT):
            if policy.as_ is PolicyType.RESTRICTIVE:
                continue
            if not policy.with_check:
                yield (
                    f"policy {policy.name!r} covers INSERT with no with_check; INSERT "
                    f"ignores using, so this policy constrains nothing"
                )

    return check


def no_unconditional_using(**kwargs) -> SchemaControlPolicy:
    """A permissive policy of ``using (true)`` protects nothing.

    Permissive policies are OR-ed together, so one unconditional policy makes
    every other policy on the table irrelevant for that command. It is a
    perfectly reasonable thing to write deliberately -- hence an exemption with
    a reason rather than a rule you cannot express.
    """

    @schema_control_policy(name="no_unconditional_using", **kwargs)
    def check(table: ControlledTable):
        for policy in table.policies:
            if policy.as_ is PolicyType.RESTRICTIVE:
                continue
            clause = (policy.using or "").strip().lower().replace(" ", "")
            if clause in _UNCONDITIONAL:
                yield (
                    f"permissive policy {policy.name!r} uses {policy.using!r}, which "
                    f"matches every row and overrides every other permissive policy "
                    f"for {policy.for_}"
                )

    return check


def column_privileges_are_valid(**kwargs) -> SchemaControlPolicy:
    """Column grants must name a privilege PostgreSQL accepts on a column.

    ``DELETE`` is the one that catches people: it reads naturally alongside the
    other three, but it is a table-level privilege only, and
    ``GRANT DELETE (col)`` is a syntax error rather than a no-op.
    """

    @schema_control_policy(name="column_privileges_are_valid", **kwargs)
    def check(table: ControlledTable):
        for column in table.columns:
            for rule in column.rules:
                if rule.operation.upper() not in _COLUMN_PRIVILEGES:
                    yield Violation(
                        f"{rule.action} {rule.operation} to {rule.role!r} is not a "
                        f"column privilege; PostgreSQL accepts only "
                        f"{', '.join(sorted(_COLUMN_PRIVILEGES))}",
                        column=column.name,
                    )

    return check


#: Every builder :func:`use_recommended` attaches when given no explicit list.
RECOMMENDED: tuple = (
    rls_required,
    policies_require_rls,
    every_command_has_a_policy,
    writes_require_with_check,
    no_unconditional_using,
    column_privileges_are_valid,
)


def use_recommended(
    *policies: Callable[..., SchemaControlPolicy],
    on: Union[str, Iterable[str], None] = None,
    exempt: Optional[Iterable[Any]] = None,
    severity: Severity = Severity.ERROR,
) -> List[SchemaControlPolicy]:
    """Declare the recommended control policies, or the ones named.

    ``on`` and ``exempt`` are passed through to each, so they behave exactly as
    a hand-written :func:`~pgalchemy.schema_control.schema_control_policy`
    would. Returns the policies, in case you want to reference one in a later
    exemption.

    ``severity=Severity.WARNING`` downgrades the whole set, which is how to
    introduce these to a codebase that does not pass yet: the report stays
    green while every failure is still printed.
    """
    builders = policies or RECOMMENDED
    for builder in builders:
        if isinstance(builder, SchemaControlPolicy):
            raise TypeError(
                f"use_recommended() takes the builders from pgalchemy.control_policies, "
                f"not an already-declared policy, but was handed {builder!r}. Import the "
                f"builder -- from pgalchemy.control_policies import {builder.name} -- or "
                f"drop the argument if {builder.name!r} is your own policy, which is "
                f"already registered and needs nothing here."
            )
    built = [builder(on=on, exempt=exempt) for builder in builders]
    if severity is not Severity.ERROR:
        for policy in built:
            _downgrade(policy, severity)
    return built


def _downgrade(policy: SchemaControlPolicy, severity: Severity) -> None:
    """Re-severity every violation a policy produces.

    Wrapping the body rather than adding a severity argument to every check
    keeps the checks themselves stating only what is wrong, and leaves how
    loudly to say it a decision for the project.
    """
    original = policy.check

    def restated(table: ControlledTable):
        for violation in original(table) or ():
            if isinstance(violation, str):
                violation = Violation(violation)
            violation.severity = severity
            yield violation

    policy.check = restated
