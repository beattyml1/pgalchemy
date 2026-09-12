"""Schema control policies: attachment, exemption, reporting and the built-ins.

These are pure unit tests. Control policies read declared state only -- nothing
here reaches a database, which is also why the Alembic hook can run in offline
``--sql`` mode.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import Boolean, Column, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import declarative_base

from pgalchemy import (
    All,
    ControlledTable,
    ExemptionRecord,
    Policy,
    PolicyCommands,
    PolicyType,
    SchemaControlViolation,
    Severity,
    Violation,
    allow_for_column,
    evaluate_control_policies,
    rls,
    rls_base,
    schema_control_exception,
    schema_control_policy,
    security_review,
)
from pgalchemy.control_policies import (
    RECOMMENDED,
    column_privileges_are_valid,
    every_command_has_a_policy,
    no_unconditional_using,
    policies_require_rls,
    rls_required,
    use_recommended,
    writes_require_with_check,
)
from pgalchemy.registry import registry


@pytest.fixture()
def Secure():
    """A model with RLS on and a full permissive policy set -- the happy path."""
    Base = rls_base(declarative_base())

    class Widget(Base):
        __tablename__ = "widgets"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)

    match = "owner_id = 1"
    Policy("pol_widgets_select", on=Widget, for_=PolicyCommands.SELECT, using=match)
    Policy("pol_widgets_delete", on=Widget, for_=PolicyCommands.DELETE, using=match)
    Policy("pol_widgets_update", on=Widget, for_=PolicyCommands.UPDATE, using=match, with_check=match)
    Policy("pol_widgets_insert", on=Widget, for_=PolicyCommands.INSERT, with_check=match)
    return Widget


@pytest.fixture()
def Bare():
    """A model with no RLS and no policies at all."""
    Base = declarative_base()

    class Country(Base):
        __tablename__ = "countries"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    return Country


def messages(report):
    return [violation.message for violation in report.violations]


def fired(policy, model) -> bool:
    """Whether ``policy`` objects to ``model``."""
    return bool(policy.evaluate(ControlledTable(model.__table__)))


# -- attachment ----------------------------------------------------------------


class TestAttachment:
    def test_a_policy_with_no_schema_governs_every_schema(self, Bare):
        seen = []

        @schema_control_policy
        def record(table):
            seen.append(table.qualified_name)

        evaluate_control_policies(Bare.metadata)

        assert seen == ["public.countries"]

    def test_a_policy_only_governs_the_schemas_it_names(self):
        Base = declarative_base()

        class Report(Base):
            __tablename__ = "reports"
            __table_args__ = {"schema": "app"}
            id = Column(Integer, primary_key=True)

        class Doc(Base):
            __tablename__ = "docs"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        seen = []

        @schema_control_policy(on="app")
        def record(table):
            seen.append(table.qualified_name)

        evaluate_control_policies(Base.metadata)

        assert seen == ["app.reports"]

    def test_a_policy_may_name_several_schemas(self):
        Base = declarative_base()

        class Report(Base):
            __tablename__ = "reports"
            __table_args__ = {"schema": "app"}
            id = Column(Integer, primary_key=True)

        class Doc(Base):
            __tablename__ = "docs"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        seen = []

        @schema_control_policy(on=["app", "public"])
        def record(table):
            seen.append(table.qualified_name)

        evaluate_control_policies(Base.metadata)

        assert sorted(seen) == ["app.reports", "public.docs"]

    def test_a_table_declared_without_a_schema_is_governed_as_public(self):
        """The implicit/explicit ``public`` mismatch must not let a table escape.

        A Table with no ``__table_args__`` has ``schema is None`` but lives in
        ``public`` all the same, so ``on="public"`` has to catch it.
        """
        Base = declarative_base()

        class Note(Base):
            __tablename__ = "notes"
            id = Column(Integer, primary_key=True)

        seen = []

        @schema_control_policy(on="public")
        def record(table):
            seen.append(table.qualified_name)

        evaluate_control_policies(Base.metadata)

        assert seen == ["public.notes"]

    def test_declaring_a_policy_registers_it(self):
        @schema_control_policy(on="public")
        def noop(table):
            return None

        assert noop in registry.control_policies

    def test_a_policy_stays_callable_as_the_original_function(self, Bare):
        @schema_control_policy
        def noop(table):
            return "objection"

        assert noop(ControlledTable(Bare.__table__)) == "objection"

    def test_a_positional_non_callable_is_rejected(self):
        with pytest.raises(TypeError, match="must wrap a function"):
            schema_control_policy("public")


# -- exemption -----------------------------------------------------------------


class TestExemption:
    def test_a_model_can_be_exempted_from_one_policy(self, Bare):
        @schema_control_policy(on="public")
        def always(table):
            yield "nope"

        schema_control_exception(always, reason="reference data")(Bare)
        report = evaluate_control_policies(Bare.metadata)

        assert report.violations == []
        assert report.exemptions == [
            ExemptionRecord("public.countries", always, "reference data", "model")
        ]

    def test_an_exemption_is_specific_to_the_policies_it_names(self, Bare):
        @schema_control_policy(on="public")
        def first(table):
            yield "first objects"

        @schema_control_policy(on="public")
        def second(table):
            yield "second objects"

        schema_control_exception(first, reason="reference data")(Bare)
        report = evaluate_control_policies(Bare.metadata)

        assert messages(report) == ["second objects"]

    def test_all_exempts_a_table_from_every_policy(self, Bare):
        @schema_control_policy(on="public")
        def first(table):
            yield "first objects"

        @schema_control_policy(on="public")
        def second(table):
            yield "second objects"

        schema_control_exception(All.All, reason="migrations bookkeeping")(Bare)
        report = evaluate_control_policies(Bare.metadata)

        assert report.violations == []
        assert len(report.exemptions) == 2

    def test_a_policy_can_carry_its_own_exemptions(self, Bare):
        @schema_control_policy(on="public", exempt=[Bare])
        def always(table):
            yield "nope"

        report = evaluate_control_policies(Bare.metadata)
        record = report.exemptions[0]

        assert report.violations == []
        # exempt= gives no reason to record, and the review must be able to say so.
        assert record.source == "policy" and record.reason is None

    def test_exempt_accepts_a_qualified_name_string(self, Bare):
        @schema_control_policy(on="public", exempt=["public.countries"])
        def always(table):
            yield "nope"

        assert evaluate_control_policies(Bare.metadata).violations == []

    def test_an_exemption_works_on_a_core_table(self, Bare):
        @schema_control_policy(on="public")
        def always(table):
            yield "nope"

        schema_control_exception(always, reason="core table")(Bare.__table__)

        assert evaluate_control_policies(Bare.metadata).violations == []

    def test_a_reason_is_required(self):
        @schema_control_policy(on="public")
        def always(table):
            yield "nope"

        with pytest.raises(TypeError):
            schema_control_exception(always)
        with pytest.raises(ValueError, match="non-empty reason"):
            schema_control_exception(always, reason="  ")

    def test_at_least_one_policy_is_required(self):
        with pytest.raises(ValueError, match="at least one control policy"):
            schema_control_exception(reason="because")

    def test_exempting_from_a_non_policy_is_rejected(self):
        with pytest.raises(TypeError, match="expected a schema control policy"):
            schema_control_exception("rls_required", reason="because")


# -- ControlledTable -----------------------------------------------------------


class TestControlledTable:
    def test_it_reports_the_declared_rls_state(self, Secure):
        table = ControlledTable(Secure.__table__)

        assert table.rls_enabled
        assert table.rls_declared
        assert not table.rls_forced

    def test_rls_declared_distinguishes_opted_out_from_never_considered(self, Bare):
        Base = rls_base(declarative_base())

        @rls(enabled=False)
        class OptedOut(Base):
            __tablename__ = "opted_out"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        opted_out = ControlledTable(OptedOut.__table__)
        never = ControlledTable(Bare.__table__)

        assert opted_out.rls_declared and not opted_out.rls_enabled
        assert not never.rls_declared and not never.rls_enabled

    def test_policies_for_expands_all(self):
        Base = rls_base(declarative_base())

        class Thing(Base):
            __tablename__ = "things"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_things_all", on=Thing, for_=PolicyCommands.ALL, using="true")
        table = ControlledTable(Thing.__table__)

        for command in PolicyCommands:
            assert [p.name for p in table.policies_for(command)] == ["pol_things_all"]
        assert table.commands_covered == {
            PolicyCommands.SELECT,
            PolicyCommands.INSERT,
            PolicyCommands.UPDATE,
            PolicyCommands.DELETE,
        }

    def test_restrictive_policies_do_not_count_as_coverage(self):
        """A restrictive policy narrows; alone it leaves the command denied."""
        Base = rls_base(declarative_base())

        class Thing(Base):
            __tablename__ = "things"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy(
            "pol_things_restrict",
            on=Thing,
            as_=PolicyType.RESTRICTIVE,
            for_=PolicyCommands.SELECT,
            using="owner_id = 1",
        )

        assert ControlledTable(Thing.__table__).commands_covered == set()

    def test_it_collects_column_rules_and_roles(self):
        Base = declarative_base()

        class User(Base):
            __tablename__ = "users"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)
            is_admin = allow_for_column(PolicyCommands.SELECT, "app_reader")(Column(Boolean))

        table = ControlledTable(User.__table__)
        column = table.column("is_admin")

        assert column.roles == {"app_reader"}
        assert len(column.grants) == 1 and not column.revocations
        assert table.roles == {"app_reader"}
        assert table.has_column("is_admin") and not table.has_column("nope")

    def test_indexed_matches_a_leading_prefix(self):
        Base = declarative_base()

        class Event(Base):
            __tablename__ = "events"
            __table_args__ = (
                Index("ix_events_tenant_created", "tenant_id", "created_at"),
                UniqueConstraint("slug"),
                {"schema": "public"},
            )
            id = Column(Integer, primary_key=True)
            tenant_id = Column(Integer)
            created_at = Column(Integer)
            slug = Column(String(20))
            other = Column(Integer)

        table = ControlledTable(Event.__table__)

        assert table.indexed("tenant_id")
        assert table.indexed("tenant_id", "created_at")
        assert table.indexed("id")           # primary key
        assert table.indexed("slug")         # unique constraint
        assert not table.indexed("created_at")   # not the leading column
        assert not table.indexed("other")
        assert not table.indexed()

    def test_the_same_table_in_two_metadatas_is_evaluated_once(self, Secure):
        """``env.py`` rebuilds tables with ``to_metadata()``; that is not two tables."""
        from sqlalchemy import MetaData

        other = MetaData()
        Secure.__table__.to_metadata(other)

        seen = []

        @schema_control_policy(on="public")
        def record(table):
            seen.append(table.qualified_name)

        evaluate_control_policies([Secure.metadata, other])

        assert seen == ["public.widgets"]


# -- violations and the report -------------------------------------------------


class TestReport:
    def test_a_policy_that_yields_nothing_passes(self, Secure):
        @schema_control_policy(on="public")
        def quiet(table):
            return None

        report = evaluate_control_policies(Secure.metadata)

        assert report.ok and report.violations == []
        assert report.evaluated == 1

    def test_a_yielded_string_becomes_an_error(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            yield "something is wrong"

        report = evaluate_control_policies(Bare.metadata)
        violation = report.violations[0]

        assert violation.severity is Severity.ERROR
        assert violation.table == "public.countries"
        assert violation.policy.name == "objects"
        assert violation.location == "public.countries"

    def test_a_violation_can_name_a_column(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            yield Violation("bad column", column="id")

        violation = evaluate_control_policies(Bare.metadata).violations[0]

        assert violation.location == "public.countries.id"

    def test_warnings_do_not_fail_the_report(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            yield Violation("worth a look", severity=Severity.WARNING)

        report = evaluate_control_policies(Bare.metadata)

        assert report.ok
        assert report.warnings and not report.errors

        with pytest.warns(UserWarning, match="worth a look"):
            report.raise_for_status()

    def test_raise_for_status_raises_on_an_error(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            yield "something is wrong"

        report = evaluate_control_policies(Bare.metadata)

        with pytest.raises(SchemaControlViolation) as excinfo:
            report.raise_for_status()
        assert excinfo.value.report is report
        assert "something is wrong" in str(excinfo.value)

    def test_raise_for_status_returns_the_report_when_clean(self, Secure):
        report = evaluate_control_policies(Secure.metadata)

        assert report.raise_for_status() is report

    def test_a_clean_report_says_so(self, Secure):
        assert "no violations" in str(evaluate_control_policies(Secure.metadata))

    def test_the_report_formats_violations_and_exemptions(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            yield "something is wrong"

        @schema_control_policy(on="public")
        def skipped(table):
            yield "never seen"

        schema_control_exception(skipped, reason="deliberate")(Bare)
        text = str(evaluate_control_policies(Bare.metadata))

        assert "1 violation, 1 exemption" in text
        assert "public.countries" in text and "something is wrong" in text
        assert "exempt  public.countries  skipped  -- deliberate" in text

    def test_an_unsupported_return_value_is_rejected(self, Bare):
        @schema_control_policy(on="public")
        def objects(table):
            return 42

        with pytest.raises(TypeError, match="Expected None, a string, a Violation"):
            evaluate_control_policies(Bare.metadata)

    def test_policies_can_be_chosen_explicitly(self, Bare):
        @schema_control_policy(on="public")
        def chosen(table):
            yield "chosen"

        @schema_control_policy(on="public")
        def ignored(table):
            yield "ignored"

        report = evaluate_control_policies(Bare.metadata, policies=[chosen])

        assert messages(report) == ["chosen"]


# -- the built-ins -------------------------------------------------------------


class TestBuiltins:
    def test_the_happy_path_passes_every_recommended_policy(self, Secure):
        use_recommended(on="public")

        assert evaluate_control_policies(Secure.metadata).ok

    def test_use_recommended_builds_all_of_them(self):
        built = use_recommended(on="public")

        assert len(built) == len(RECOMMENDED)
        assert {p.name for p in built} == {b(on="x").name for b in RECOMMENDED}

    def test_use_recommended_rejects_an_already_declared_policy(self):
        """The builders take ``on=``; a declared policy has already been attached."""

        @schema_control_policy(on="public")
        def mine(table):
            return None

        with pytest.raises(TypeError, match="takes the builders"):
            use_recommended(mine, on="public")

    def test_the_report_aligns_warnings_with_errors(self, Bare):
        @schema_control_policy(on="public")
        def mixed(table):
            yield Violation("a warning", severity=Severity.WARNING)
            yield "an error"

        lines = [
            line for line in str(evaluate_control_policies(Bare.metadata)).splitlines()
            if "public.countries" in line
        ]

        assert len(lines) == 2
        assert len({line.index("public.countries") for line in lines}) == 1

    def test_use_recommended_can_build_a_subset(self):
        built = use_recommended(rls_required, on="public")

        assert [p.name for p in built] == ["rls_required"]

    def test_use_recommended_can_downgrade_to_warnings(self, Bare):
        use_recommended(rls_required, on="public", severity=Severity.WARNING)
        report = evaluate_control_policies(Bare.metadata)

        assert report.ok
        assert report.warnings[0].message == "row level security is not enabled"

    def test_rls_required(self, Secure, Bare):
        policy = rls_required(on="public")

        assert not fired(policy, Secure)
        assert fired(policy, Bare)

    def test_rls_required_distinguishes_an_explicit_opt_out(self):
        Base = rls_base(declarative_base())

        @rls(enabled=False)
        class OptedOut(Base):
            __tablename__ = "opted_out"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        violations = rls_required(on="public").evaluate(ControlledTable(OptedOut.__table__))

        assert violations[0].message == "row level security is declared but switched off"

    def test_policies_require_rls(self):
        Base = declarative_base()

        class Loose(Base):
            __tablename__ = "loose"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_loose_select", on=Loose, for_=PolicyCommands.SELECT, using="true")
        policy = policies_require_rls(on="public")

        message = policy.evaluate(ControlledTable(Loose.__table__))[0].message
        assert message == (
            "policy 'pol_loose_select' is declared but row level security is not "
            "enabled, so it is never consulted"
        )

    def test_policies_require_rls_is_quiet_when_there_are_no_policies(self, Bare):
        assert not fired(policies_require_rls(on="public"), Bare)

    def test_every_command_has_a_policy(self, Secure):
        Base = rls_base(declarative_base())

        class Partial(Base):
            __tablename__ = "partial"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_partial_select", on=Partial, for_=PolicyCommands.SELECT, using="true")
        policy = every_command_has_a_policy(on="public")

        assert not fired(policy, Secure)
        message = policy.evaluate(ControlledTable(Partial.__table__))[0].message
        assert "INSERT" in message and "UPDATE" in message and "DELETE" in message

    def test_every_command_has_a_policy_is_quiet_when_rls_is_off(self, Bare):
        assert not fired(every_command_has_a_policy(on="public"), Bare)

    def test_writes_require_with_check_on_update(self):
        Base = rls_base(declarative_base())

        class Leaky(Base):
            __tablename__ = "leaky"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_leaky_update", on=Leaky, for_=PolicyCommands.UPDATE, using="owner_id = 1")
        violations = writes_require_with_check(on="public").evaluate(
            ControlledTable(Leaky.__table__)
        )

        assert "update a row out of their own set" in violations[0].message

    def test_writes_require_with_check_on_insert(self):
        Base = rls_base(declarative_base())

        class Leaky(Base):
            __tablename__ = "leaky"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_leaky_insert", on=Leaky, for_=PolicyCommands.INSERT, using="owner_id = 1")
        violations = writes_require_with_check(on="public").evaluate(
            ControlledTable(Leaky.__table__)
        )

        assert "INSERT ignores using" in violations[0].message

    def test_writes_require_with_check_passes_the_happy_path(self, Secure):
        assert not fired(writes_require_with_check(on="public"), Secure)

    def test_no_unconditional_using(self, Secure):
        Base = rls_base(declarative_base())

        class Open(Base):
            __tablename__ = "open_table"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy("pol_open_select", on=Open, for_=PolicyCommands.SELECT, using="true")
        policy = no_unconditional_using(on="public")

        assert not fired(policy, Secure)
        assert "matches every row" in policy.evaluate(ControlledTable(Open.__table__))[0].message

    def test_no_unconditional_using_ignores_restrictive_policies(self):
        Base = rls_base(declarative_base())

        class Narrowed(Base):
            __tablename__ = "narrowed"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)

        Policy(
            "pol_narrowed",
            on=Narrowed,
            as_=PolicyType.RESTRICTIVE,
            for_=PolicyCommands.SELECT,
            using="true",
        )

        assert not fired(no_unconditional_using(on="public"), Narrowed)

    def test_column_privileges_are_valid(self):
        Base = declarative_base()

        class User(Base):
            __tablename__ = "users"
            __table_args__ = {"schema": "public"}
            id = Column(Integer, primary_key=True)
            secret = allow_for_column(PolicyCommands.DELETE, "app_reader")(Column(String(10)))
            fine = allow_for_column(PolicyCommands.SELECT, "app_reader")(Column(String(10)))

        violations = column_privileges_are_valid(on="public").evaluate(
            ControlledTable(User.__table__)
        )

        assert len(violations) == 1
        assert violations[0].column == "secret"
        assert "not a column privilege" in violations[0].message


# -- the security review -------------------------------------------------------


@pytest.fixture()
def reviewable():
    """A schema with one of everything the review is meant to surface."""
    Base = rls_base(declarative_base())

    class Document(Base):
        __tablename__ = "documents"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)
        owner_id = Column(Integer)
        tenant_id = Column(Integer)

    Policy(
        "pol_documents_all",
        on=Document,
        for_=PolicyCommands.ALL,
        using="owner_id = 1",
        with_check="owner_id = 1",
    )

    @rls(enabled=False)
    class Country(Base):
        __tablename__ = "countries"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    class AlembicVersion(Base):
        __tablename__ = "alembic_version"
        __table_args__ = {"schema": "public"}
        version_num = Column(String(32), primary_key=True)

    @schema_control_policy(on="public")
    def tenant_columns_are_indexed(table):
        if table.has_column("tenant_id") and not table.indexed("tenant_id"):
            yield Violation(
                "tenant_id is not indexed", severity=Severity.WARNING, column="tenant_id"
            )

    built = {p.name: p for p in use_recommended(rls_required, on="public", exempt=[AlembicVersion])}
    schema_control_exception(
        built["rls_required"], reason="public reference data, no tenant column"
    )(Country)

    return Base


class TestSecurityReview:
    def test_it_lists_exemptions_with_their_reason_and_source(self, reviewable):
        review = security_review(reviewable.metadata)

        assert review["exemptions"] == [
            {
                "table": "public.alembic_version",
                "policy": "rls_required",
                "reason": None,
                "source": "policy",
            },
            {
                "table": "public.countries",
                "policy": "rls_required",
                "reason": "public reference data, no tenant column",
                "source": "model",
            },
        ]

    def test_it_lists_warnings_with_their_column(self, reviewable):
        review = security_review(reviewable.metadata)

        assert review["warnings"] == [
            {
                "table": "public.documents",
                "column": "tenant_id",
                "policy": "tenant_columns_are_indexed",
                "message": "tenant_id is not indexed",
            }
        ]

    def test_it_lists_the_policies_in_force(self, reviewable):
        """Without the roster, deleting a check reads as risk going down."""
        review = security_review(reviewable.metadata)

        assert review["control_policies"] == [
            {"name": "rls_required", "schemas": ["public"]},
            {"name": "tenant_columns_are_indexed", "schemas": ["public"]},
        ]

    def test_a_policy_governing_every_schema_is_shown_as_a_star(self, Bare):
        @schema_control_policy
        def everywhere(table):
            return None

        assert security_review(Bare.metadata)["control_policies"] == [
            {"name": "everywhere", "schemas": ["*"]}
        ]

    def test_errors_are_not_in_the_review(self, Bare):
        """An error aborts the run, so it is never a standing state to review."""

        @schema_control_policy(on="public")
        def objects(table):
            yield "a hard failure"

        review = security_review(Bare.metadata)

        assert review["warnings"] == [] and review["exemptions"] == []
        assert "a hard failure" not in str(review)

    def test_it_is_json_serialisable(self, reviewable):
        """Plain data only -- no enums, no objects, nothing a dumper chokes on."""
        review = security_review(reviewable.metadata)
        round_tripped = json.loads(json.dumps(review))

        assert round_tripped == review

    def test_it_is_stable_across_runs(self, reviewable):
        assert security_review(reviewable.metadata) == security_review(reviewable.metadata)

    def test_it_does_not_depend_on_declaration_order(self):
        """Two schemas declared in opposite orders must review identically."""

        def build(reverse: bool):
            registry.clear()
            Base = declarative_base()

            class A(Base):
                __tablename__ = "aaa"
                __table_args__ = {"schema": "public"}
                id = Column(Integer, primary_key=True)

            class B(Base):
                __tablename__ = "bbb"
                __table_args__ = {"schema": "public"}
                id = Column(Integer, primary_key=True)

            @schema_control_policy(on="public", name="second")
            def second(table):
                return None

            @schema_control_policy(on="public", name="first")
            def first(table):
                return None

            targets = [B, A] if reverse else [A, B]
            for target in targets:
                schema_control_exception(first, second, reason="deliberate")(target)
            return security_review(Base.metadata)

        assert build(reverse=False) == build(reverse=True)

    def test_an_empty_schema_reviews_as_empty_lists(self, Bare):
        assert security_review(Bare.metadata) == {
            "control_policies": [],
            "exemptions": [],
            "warnings": [],
        }

    def test_the_report_method_and_the_function_agree(self, reviewable):
        report = evaluate_control_policies(reviewable.metadata)

        assert report.security_review() == security_review(reviewable.metadata)

    def test_a_security_team_can_assert_every_exemption_gave_a_reason(self, reviewable):
        """The shape a reviewing team is expected to enforce for themselves."""
        review = security_review(reviewable.metadata)
        unjustified = [e for e in review["exemptions"] if not e["reason"]]

        assert [e["table"] for e in unjustified] == ["public.alembic_version"]

    def test_it_snapshots(self, reviewable, snapshot):
        snapshot.snapshot_dir = "tests/snapshots"
        snapshot.assert_match(
            json.dumps(security_review(reviewable.metadata), indent=2) + "\n",
            "security_review.json",
        )
