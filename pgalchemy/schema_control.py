"""Schema control policies: project-wide guardrails over declared permissioning.

Everything else in pgalchemy describes permissioning one table at a time -- RLS
flags, :class:`~pgalchemy.policy.Policy` objects, column grants. Nothing checks
those declarations against each other, or against a standard the project has
decided on. A table can declare policies and never enable row level security, in
which case the policies silently do nothing; an ``UPDATE`` policy can carry
``using`` without ``with_check``, letting a caller update a row they own into one
they do not; a new model can simply be added with no protection at all. None of
those is visible until production.

A **schema control policy** is the guardrail over all of it, modelled on AWS's
Service Control Policies. The mapping is exact, and worth holding in mind when
reading this module:

============================  ==========================================
AWS                           pgalchemy
============================  ==========================================
IAM policy                    :class:`~pgalchemy.policy.Policy`
  -- grants access on one       -- one ``CREATE POLICY`` on one table
     specific resource
Service Control Policy        :class:`SchemaControlPolicy`
  -- attaches to an OU          -- attaches to a schema
  -- governs every account      -- governs every table in that schema
  -- can only ever refuse       -- can only ever refuse
============================  ==========================================

That last row is the important one. A control policy emits no SQL and changes no
declaration; its only power is to refuse to let a non-compliant schema through::

    @schema_control_policy(on="public")
    def rls_required(table: ControlledTable):
        if not table.rls_enabled:
            yield "row level security is not enabled"

    evaluate_control_policies(Base.metadata).raise_for_status()

"Schema" rather than "security" is deliberate. It names the subject being
governed rather than one category of check, so a later rule about audit columns,
retention triggers or required indexes fits the name without stretching it.

Declaring a control policy registers it, exactly as constructing a ``Policy``
does, so importing the module that defines one is all the wiring there is. See
:mod:`pgalchemy.control_policies` for the ones shipped with the library.
"""
from __future__ import annotations

import warnings
from collections.abc import Iterable as IterableABC
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from sqlalchemy import Column, MetaData, Table, UniqueConstraint

from .cls import All, ColumnSecurityRule, column_is_managed, column_rules
from .policy import Policy, PolicyCommands, PolicyType
from .registry import DEFAULT_SCHEMA, TableKey, registry, table_key
from .rls import RlsData

#: The commands a policy can actually be declared for, once
#: :attr:`~pgalchemy.policy.PolicyCommands.ALL` is expanded. ``ALL`` is a
#: shorthand in ``CREATE POLICY``, not a fifth command, so anything reasoning
#: per-command has to expand it or it will conclude a table protected by one
#: ``for ALL`` policy covers nothing.
CONCRETE_COMMANDS: Tuple[PolicyCommands, ...] = (
    PolicyCommands.SELECT,
    PolicyCommands.INSERT,
    PolicyCommands.UPDATE,
    PolicyCommands.DELETE,
)


def normalised_key(target: Any) -> TableKey:
    """``(schema, table)`` for ``target``, with the schema always spelled out.

    ``table_key`` preserves a ``None`` schema, because that is what a ``Table``
    declared without ``__table_args__`` carries. Two declarations of the same
    table -- one implicit, one written as ``schema="public"`` -- therefore
    produce different keys, and an exemption declared one way would not match a
    table declared the other. Control policies compare keys constantly, so they
    normalise once here instead.
    """
    schema, name = table_key(target)
    return (schema or DEFAULT_SCHEMA, name)


class Severity(Enum):
    """How loudly a violation is reported.

    ``ERROR`` fails :meth:`ControlReport.raise_for_status`; ``WARNING`` is
    surfaced through :mod:`warnings` and leaves the report passing, which is
    what a newly introduced control policy wants while a codebase catches up.
    """

    ERROR = "ERROR"
    WARNING = "WARNING"

    def __str__(self) -> str:
        return self.value


class Violation:
    """One thing a control policy objected to.

    A policy body can simply yield a string, which becomes an ``ERROR``-severity
    violation. Construct one of these instead to set the severity or to point at
    a particular column::

        yield Violation("tenant_id is not indexed",
                        severity=Severity.WARNING, column="tenant_id")
    """

    def __init__(
        self,
        message: str,
        severity: Severity = Severity.ERROR,
        column: Optional[str] = None,
    ):
        self.message = message
        self.severity = severity
        self.column = column
        # Filled in by the evaluator. A policy body knows what is wrong but not
        # which policy it is or which table it was handed, and making every body
        # repeat both would be noise -- so the evaluator stamps them on after
        # the fact.
        self.policy: Optional["SchemaControlPolicy"] = None
        self.table: Optional[str] = None

    def _attach(self, policy: "SchemaControlPolicy", table: "ControlledTable") -> "Violation":
        self.policy = policy
        self.table = table.qualified_name
        return self

    @property
    def location(self) -> str:
        """``public.documents`` or ``public.documents.owner_id``."""
        if self.column:
            return f"{self.table}.{self.column}"
        return self.table or "<unknown>"

    def __repr__(self) -> str:
        name = self.policy.name if self.policy else "<unattached>"
        return f"Violation({self.location} {name}: {self.message!r})"


class ExemptionRecord(NamedTuple):
    """One control policy skipped for one table, and why.

    ``source`` is ``"model"`` for an exemption declared with
    :func:`schema_control_exception` and ``"policy"`` for one listed in
    ``exempt=`` on the policy itself. Only the first carries a ``reason``; the
    second has none to give, which is exactly the thing a security review wants
    to be able to spot, so it is a field rather than a turn of phrase.
    """

    table: str
    policy: "SchemaControlPolicy"
    reason: Optional[str]
    source: str


class Exemption:
    """A table's licence to ignore one or more control policies.

    Declared with :func:`schema_control_exception`, or as ``exempt=`` on the
    policy itself. Exemptions are reported rather than swallowed: the whole
    point of a guardrail is that stepping around it stays visible.
    """

    def __init__(
        self,
        policies: Sequence[Union["SchemaControlPolicy", All]],
        reason: str,
        target: Any = None,
    ):
        self.policies = tuple(policies)
        self.reason = reason
        self.target = target

    def covers(self, policy: "SchemaControlPolicy") -> bool:
        return any(item is All.All or item is policy for item in self.policies)

    def __repr__(self) -> str:
        names = ", ".join(
            "*" if item is All.All else item.name for item in self.policies
        )
        return f"Exemption({names}, reason={self.reason!r})"


class ControlledColumn:
    """A column, with the privilege rules declared on it."""

    def __init__(self, column: Column):
        self.column = column
        self.name = column.name
        self.rules: List[ColumnSecurityRule] = column_rules(column)

    @property
    def grants(self) -> List[ColumnSecurityRule]:
        return [rule for rule in self.rules if rule.action == "GRANT"]

    @property
    def revocations(self) -> List[ColumnSecurityRule]:
        return [rule for rule in self.rules if rule.action == "REVOKE"]

    @property
    def roles(self) -> Set[str]:
        return {rule.role for rule in self.rules}

    def is_managed_for(self, role: str) -> bool:
        """Whether pgalchemy owns this role's privileges on this column."""
        return column_is_managed(role, self.column)

    def __repr__(self) -> str:
        return f"ControlledColumn({self.name!r}, rules={len(self.rules)})"


class ControlledTable:
    """Everything pgalchemy knows about one table, in one place.

    This is what a control policy body is handed. The underlying state lives in
    three unrelated places -- RLS flags and policies in the
    :data:`~pgalchemy.registry.registry`, column privileges on ``Column.info`` --
    and assembling them is most of what this class is for.

    Every lookup here tolerates the implicit/explicit ``public`` mismatch: a
    ``Table`` declared without ``__table_args__`` has ``schema is None`` but
    lives in ``public`` all the same, and a policy bound to the explicitly
    spelled version must still be found.
    """

    def __init__(self, table: Table, model: Optional[type] = None):
        self.table = table
        self.model = model
        self.schema = table.schema or DEFAULT_SCHEMA
        self.name = table.name
        self.key: TableKey = (self.schema, self.name)
        self.qualified_name = f"{self.schema}.{self.name}"
        self.columns: List[ControlledColumn] = [
            ControlledColumn(column) for column in table.columns
        ]

    # -- row level security -------------------------------------------------
    @property
    def rls(self) -> Optional[RlsData]:
        """The declared :class:`~pgalchemy.rls.RlsData`, or ``None``."""
        return registry.get_rls(self.table)

    @property
    def rls_declared(self) -> bool:
        """Whether RLS was declared at all, either way.

        ``is_rls_enabled`` answers ``False`` both for a table that opted out
        with ``@rls(enabled=False)`` and for one nobody ever considered. A
        control policy usually wants to treat those differently.
        """
        return self.rls is not None

    @property
    def rls_enabled(self) -> bool:
        data = self.rls
        return bool(data and data.active)

    @property
    def rls_forced(self) -> bool:
        data = self.rls
        return bool(data and data.force)

    # -- policies -----------------------------------------------------------
    @property
    def policies(self) -> List[Policy]:
        by_name: Dict[str, Policy] = {}
        for key in ((self.table.schema, self.name), (self.schema, self.name), (None, self.name)):
            by_name.update(registry.policies.get(key, {}))
        return list(by_name.values())

    def policies_for(self, command: PolicyCommands) -> List[Policy]:
        """Policies that apply to ``command``, with ``ALL`` expanded."""
        return [
            policy
            for policy in self.policies
            if policy.for_ in (command, PolicyCommands.ALL, None)
        ]

    @property
    def commands_covered(self) -> Set[PolicyCommands]:
        """Commands some *permissive* policy grants access for.

        Restrictive policies deliberately do not count. PostgreSQL AND-s them
        into whatever permissive policies already matched, so a command with
        only restrictive policies is denied outright rather than covered.
        """
        covered: Set[PolicyCommands] = set()
        for policy in self.policies:
            if policy.as_ is PolicyType.RESTRICTIVE:
                continue
            if policy.for_ in (PolicyCommands.ALL, None):
                covered.update(CONCRETE_COMMANDS)
            else:
                covered.add(policy.for_)
        return covered

    # -- columns ------------------------------------------------------------
    def column(self, name: str) -> Optional[ControlledColumn]:
        for column in self.columns:
            if column.name == name:
                return column
        return None

    def has_column(self, name: str) -> bool:
        return self.column(name) is not None

    @property
    def roles(self) -> Set[str]:
        """Every role named anywhere on this table, by a policy or a grant."""
        found: Set[str] = set()
        for policy in self.policies:
            found.update(policy.to)
        for column in self.columns:
            found.update(column.roles)
        return found

    def indexed(self, *column_names: str) -> bool:
        """Whether an index leads with exactly ``column_names``, in that order.

        Prefix matching, because that is how PostgreSQL uses a composite index:
        one on ``(tenant_id, created_at)`` serves a lookup on ``tenant_id``, but
        one on ``(created_at, tenant_id)`` does not. Primary keys and unique
        constraints count -- PostgreSQL builds an index for both.
        """
        wanted = tuple(column_names)
        if not wanted:
            return False

        candidates: List[Tuple[str, ...]] = [
            tuple(column.name for column in index.columns) for index in self.table.indexes
        ]
        primary_key = tuple(column.name for column in self.table.primary_key.columns)
        if primary_key:
            candidates.append(primary_key)
        for constraint in self.table.constraints:
            if isinstance(constraint, UniqueConstraint):
                candidates.append(tuple(column.name for column in constraint.columns))
        for column in self.table.columns:
            if column.index or column.unique:
                candidates.append((column.name,))

        return any(candidate[: len(wanted)] == wanted for candidate in candidates)

    def __repr__(self) -> str:
        return f"ControlledTable({self.qualified_name!r})"


class SchemaControlPolicy:
    """A guardrail attached to one or more schemas.

    Built by :func:`schema_control_policy`, which is how it should be declared.
    Constructing one registers it.
    """

    def __init__(
        self,
        check: Callable[[ControlledTable], Any],
        on: Union[str, Iterable[str], None] = None,
        exempt: Optional[Iterable[Any]] = None,
        name: Optional[str] = None,
    ):
        if not callable(check):
            raise TypeError(
                f"A schema control policy must wrap a function, got {check!r}. Pass "
                f"the schema as a keyword: @schema_control_policy(on='public')."
            )
        self.check = check
        self.name = name or getattr(check, "__name__", None) or repr(check)
        self.__doc__ = getattr(check, "__doc__", None)
        #: Schemas this policy attaches to, or ``None`` for every schema.
        self.schemas: Optional[frozenset] = _coerce_schemas(on)
        self.exempt: frozenset = frozenset(
            normalised_key(target) for target in (exempt or ())
        )
        registry.register_control_policy(self)

    def attaches_to(self, table: ControlledTable) -> bool:
        """Whether this policy governs ``table``'s schema at all."""
        return self.schemas is None or table.schema in self.schemas

    def evaluate(self, table: ControlledTable) -> List[Violation]:
        """Run the body against ``table`` and normalise whatever comes back."""
        return [
            violation._attach(self, table)
            for violation in _as_violations(self.check(table), self)
        ]

    def __call__(self, table: ControlledTable) -> Any:
        """Delegate to the wrapped function, so a policy stays directly testable."""
        return self.check(table)

    def __repr__(self) -> str:
        where = "*" if self.schemas is None else ", ".join(sorted(self.schemas))
        return f"SchemaControlPolicy({self.name!r}, on={where})"


def _coerce_schemas(on: Union[str, Iterable[str], None]) -> Optional[frozenset]:
    if on is None:
        return None
    if isinstance(on, str):
        return frozenset({on})
    return frozenset(item or DEFAULT_SCHEMA for item in on)


def _as_violations(result: Any, policy: SchemaControlPolicy) -> Iterator[Violation]:
    """Turn a policy body's return value into :class:`Violation` objects.

    A body may return nothing, a string, a :class:`Violation`, or an iterable of
    those -- including by being a generator, which is the usual shape.
    """
    if result is None:
        return
    # str is iterable, so it has to be caught before the iterable branch.
    if isinstance(result, (str, Violation)):
        yield _coerce_violation(result, policy)
        return
    if isinstance(result, IterableABC):
        for item in result:
            if item is None:
                continue
            yield _coerce_violation(item, policy)
        return
    raise TypeError(
        f"Schema control policy {policy.name!r} returned {result!r}. Expected None, "
        f"a string, a Violation, or an iterable of those -- most bodies yield."
    )


def _coerce_violation(item: Any, policy: SchemaControlPolicy) -> Violation:
    if isinstance(item, Violation):
        return item
    if isinstance(item, str):
        return Violation(item)
    raise TypeError(
        f"Schema control policy {policy.name!r} produced {item!r}. Expected a string "
        f"or a Violation."
    )


def schema_control_policy(
    check: Optional[Callable[[ControlledTable], Any]] = None,
    *,
    on: Union[str, Iterable[str], None] = None,
    exempt: Optional[Iterable[Any]] = None,
    name: Optional[str] = None,
):
    """Declare a control policy over every table in one or more schemas.

    Usable bare or called::

        @schema_control_policy
        def rls_required(table): ...              # every schema

        @schema_control_policy(on="public")
        def rls_required(table): ...

        @schema_control_policy(on=["public", "app"], exempt=[Country])
        def rls_required(table): ...

    ``on`` names the schema(s) governed, mirroring ``Policy(on=...)``; omit it to
    govern every schema. ``exempt`` takes models, ``Table`` objects,
    ``"schema.table"`` strings or ``(schema, table)`` tuples, for exceptions
    known where the policy is written -- see :func:`schema_control_exception`
    for the ones that belong next to the model instead.

    The body is handed a :class:`ControlledTable` and signals compliance by
    yielding nothing. Returns the :class:`SchemaControlPolicy`, so the decorated
    name can be referenced in an exemption.
    """

    def wrapper(target: Callable[[ControlledTable], Any]) -> SchemaControlPolicy:
        return SchemaControlPolicy(target, on=on, exempt=exempt, name=name)

    if check is not None:
        return wrapper(check)
    return wrapper


def schema_control_exception(*policies: Union[SchemaControlPolicy, All], reason: str):
    """Exempt the decorated model or table from one or more control policies.

    ::

        @schema_control_exception(rls_required, reason="public reference data")
        class Country(BaseModel):
            __tablename__ = "countries"

    Pass :attr:`~pgalchemy.cls.All.All` to exempt a table from every control
    policy, present and future. Usable as a plain call for Core tables, the way
    ``rls_for_table()`` is::

        schema_control_exception(rls_required, reason="...")(my_table)

    ``reason`` is required. An exemption is the one thing a reviewer most needs
    to see the justification for, and it is carried into the report rather than
    quietly removing the table from the results.
    """
    if not policies:
        raise ValueError(
            "schema_control_exception() needs at least one control policy to exempt "
            "from, or All.All to exempt from every one."
        )
    for item in policies:
        if not isinstance(item, SchemaControlPolicy) and item is not All.All:
            raise TypeError(
                f"Cannot exempt from {item!r}: expected a schema control policy or "
                f"All.All."
            )
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(
            "schema_control_exception() requires a non-empty reason, which is "
            "reported alongside the exemption."
        )

    def wrapper(target):
        registry.register_control_exception(
            normalised_key(target), Exemption(policies, reason, target)
        )
        return target

    return wrapper


class SchemaControlViolation(Exception):
    """Raised when a schema fails one or more control policies."""

    def __init__(self, report: "ControlReport"):
        self.report = report
        super().__init__(str(report))


class ControlReport:
    """The outcome of evaluating every control policy against every table."""

    def __init__(
        self,
        violations: Sequence[Violation],
        exemptions: Sequence[ExemptionRecord],
        evaluated: int,
        policies: Sequence[SchemaControlPolicy] = (),
    ):
        self.violations = list(violations)
        #: An :class:`ExemptionRecord` for each policy/table pair that was skipped.
        self.exemptions = list(exemptions)
        #: How many tables were looked at.
        self.evaluated = evaluated
        #: The policies that were evaluated, whether or not they found anything.
        self.policies = list(policies)

    @property
    def errors(self) -> List[Violation]:
        return [v for v in self.violations if v.severity is Severity.ERROR]

    @property
    def warnings(self) -> List[Violation]:
        return [v for v in self.violations if v.severity is Severity.WARNING]

    @property
    def ok(self) -> bool:
        """Whether anything error-severity was found."""
        return not self.errors

    def raise_for_status(self) -> "ControlReport":
        """Raise :class:`SchemaControlViolation` if any error was found.

        Warnings are surfaced through :mod:`warnings` and do not raise, so a
        newly added control policy can be introduced in warning mode while a
        codebase catches up with it.
        """
        for violation in self.warnings:
            warnings.warn(
                f"{violation.location}: {violation.message} "
                f"[{violation.policy.name if violation.policy else '?'}]",
                stacklevel=2,
            )
        if self.errors:
            raise SchemaControlViolation(self)
        return self

    def __str__(self) -> str:
        if not self.violations and not self.exemptions:
            return f"{self.evaluated} tables checked, no violations"

        lines: List[str] = []
        count = len(self.violations)
        header = f"{count} violation{'' if count == 1 else 's'}"
        if self.exemptions:
            n = len(self.exemptions)
            header += f", {n} exemption{'' if n == 1 else 's'}"
        lines.append(header)

        if self.violations:
            lines.append("")
            width = max(len(v.location) for v in self.violations)
            names = max(len(v.policy.name if v.policy else "?") for v in self.violations)
            for violation in self.violations:
                name = violation.policy.name if violation.policy else "?"
                # Same width either way, or the columns stop lining up.
                prefix = "  " if violation.severity is Severity.ERROR else "! "
                lines.append(
                    f"{prefix}{violation.location:<{width}}  {name:<{names}}  "
                    f"{violation.message}"
                )

        if self.exemptions:
            lines.append("")
            for record in self.exemptions:
                reason = record.reason or "no reason given"
                lines.append(
                    f"  exempt  {record.table}  {record.policy.name}  -- {reason}"
                )

        return "\n".join(lines)

    def security_review(self) -> Dict[str, Any]:
        """Everything deliberately not enforced, as plain data for a snapshot test.

        The artifact a security team signs off on. It holds the two things that
        deviate from the declared standard without failing the build --
        exemptions, where a table is excused from a policy, and warnings, where
        a violation is reported but tolerated. Errors are deliberately absent:
        they abort the run, so they can never be a standing state anybody needs
        to review.

        Everything is ``str``/``list``/``dict``/``None``, so it dumps as-is::

            import json, yaml

            def test_security_exceptions(snapshot):
                review = security_review(Base.metadata)
                snapshot.assert_match(
                    yaml.safe_dump(review, sort_keys=False), "security_review.yaml"
                )
                # or json.dumps(review, indent=2)

        Being data rather than prose, a security team can also assert on it
        directly -- ``assert all(e["reason"] for e in review["exemptions"])``
        refuses any exemption that never said why.

        ``control_policies`` lists the policies that ran, which matters more
        than it looks: deleting a control policy silently removes every
        exemption against it, and without the roster that diff reads as risk
        going down rather than a check being taken away.

        Ordering is sorted throughout and no field is padded or aligned, so a
        diff shows only what actually changed.
        """
        return {
            "control_policies": [
                {
                    "name": policy.name,
                    "schemas": (
                        ["*"] if policy.schemas is None else sorted(policy.schemas)
                    ),
                }
                for policy in sorted(
                    self.policies,
                    key=lambda p: (p.name, sorted(p.schemas or ())),
                )
            ],
            "exemptions": [
                {
                    "table": record.table,
                    "policy": record.policy.name,
                    "reason": record.reason,
                    "source": record.source,
                }
                for record in sorted(
                    self.exemptions,
                    key=lambda r: (r.table, r.policy.name, r.source),
                )
            ],
            "warnings": [
                {
                    "table": violation.table,
                    "column": violation.column,
                    "policy": violation.policy.name if violation.policy else None,
                    "message": violation.message,
                }
                for violation in sorted(
                    self.warnings,
                    key=lambda v: (
                        v.table or "",
                        v.column or "",
                        v.policy.name if v.policy else "",
                        v.message,
                    ),
                )
            ],
        }

    def __repr__(self) -> str:
        return (
            f"ControlReport(evaluated={self.evaluated}, errors={len(self.errors)}, "
            f"warnings={len(self.warnings)}, exemptions={len(self.exemptions)})"
        )


def evaluate_control_policies(
    metadata: Union[MetaData, Iterable[MetaData], None] = None,
    policies: Optional[Iterable[SchemaControlPolicy]] = None,
) -> ControlReport:
    """Evaluate control policies against every table and collect the results.

    ``metadata`` may be a :class:`~sqlalchemy.MetaData`, several of them, or be
    omitted -- in which case every mapped class is swept, the same way
    :mod:`pgalchemy.permission_patterns` finds models to apply patterns to.
    ``policies`` defaults to everything declared.

    Nothing is raised here; inspect the :class:`ControlReport`, or call its
    :meth:`~ControlReport.raise_for_status`.
    """
    # Imported here rather than at module scope: importing permission_patterns
    # installs a global Mapper event listener, which a project that only uses
    # control policies has not asked for.
    from .permission_patterns import mapped_classes

    chosen = list(registry.control_policies if policies is None else policies)
    models_by_key: Dict[TableKey, type] = {}
    for class_, table in mapped_classes():
        models_by_key[normalised_key(table)] = class_

    tables = _tables_from(metadata, mapped_classes)

    violations: List[Violation] = []
    exemptions: List[ExemptionRecord] = []
    evaluated = 0

    for table in tables:
        controlled = ControlledTable(table, models_by_key.get(normalised_key(table)))
        evaluated += 1
        declared = registry.control_exceptions.get(controlled.key, ())

        for policy in chosen:
            if not policy.attaches_to(controlled):
                continue

            if controlled.key in policy.exempt:
                exemptions.append(
                    ExemptionRecord(
                        controlled.qualified_name, policy, None, "policy"
                    )
                )
                continue

            excused = next((e for e in declared if e.covers(policy)), None)
            if excused is not None:
                exemptions.append(
                    ExemptionRecord(
                        controlled.qualified_name, policy, excused.reason, "model"
                    )
                )
                continue

            violations.extend(policy.evaluate(controlled))

    return ControlReport(violations, exemptions, evaluated, chosen)


def _tables_from(
    metadata: Union[MetaData, Iterable[MetaData], None],
    mapped_classes: Callable[[], List[Tuple[type, Table]]],
) -> List[Table]:
    """The tables to evaluate, de-duplicated by normalised key.

    ``env.py`` routinely rebuilds tables into a fresh ``MetaData``, so the same
    logical table can arrive more than once as different ``Table`` objects.
    """
    if metadata is None:
        candidates = [table for _, table in mapped_classes()]
    elif isinstance(metadata, MetaData):
        candidates = list(metadata.tables.values())
    else:
        candidates = [
            table for item in metadata for table in item.tables.values()
        ]

    seen: Dict[TableKey, Table] = {}
    for table in candidates:
        seen.setdefault(normalised_key(table), table)
    return list(seen.values())


def security_review(
    metadata: Union[MetaData, Iterable[MetaData], None] = None,
    policies: Optional[Iterable[SchemaControlPolicy]] = None,
) -> Dict[str, Any]:
    """The standing inventory of everything deliberately not enforced.

    Evaluates the control policies and returns
    :meth:`ControlReport.security_review` -- the exemptions, the warnings and
    the policies in force, as plain data ready for ``yaml.safe_dump`` or
    ``json.dumps``. See that method for what is in it and why.
    """
    return evaluate_control_policies(metadata, policies).security_review()
