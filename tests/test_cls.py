"""Column level security declarations."""
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

from pgalchemy import PolicyCommands, allow_for_column, deny_for_column
from pgalchemy.cls import (
    All,
    ColumnSecurityRule,
    column_is_managed,
    column_rules,
    manage_cls_for_combo,
)


def test_allow_returns_the_column_so_it_can_be_used_inline():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "docs"
        id = Column(Integer, primary_key=True)
        secret = allow_for_column(PolicyCommands.SELECT, "app_reader")(Column(String(20)))

    assert isinstance(Doc.__table__.c.secret, Column)
    assert column_rules(Doc.__table__.c.secret) == [
        ColumnSecurityRule("GRANT", "SELECT", "app_reader")
    ]


def test_deny_records_a_revoke_rule():
    column = deny_for_column(PolicyCommands.UPDATE, "app_user")(Column("x", Integer))

    assert column_rules(column) == [ColumnSecurityRule("REVOKE", "UPDATE", "app_user")]


def test_rules_accumulate_in_declaration_order():
    column = Column("x", Integer)
    allow_for_column(PolicyCommands.SELECT, "reader")(column)
    deny_for_column(PolicyCommands.UPDATE, "reader")(column)

    assert column_rules(column) == [
        ColumnSecurityRule("GRANT", "SELECT", "reader"),
        ColumnSecurityRule("REVOKE", "UPDATE", "reader"),
    ]


def test_rules_are_stored_as_flat_tuples_not_nested_lists():
    """Each rule must unpack into ``(action, operation, role)``."""
    column = allow_for_column(PolicyCommands.INSERT, "writer")(Column("x", Integer))

    action, operation, role = column_rules(column)[0]
    assert (action, operation, role) == ("GRANT", "INSERT", "writer")


def test_plain_strings_are_accepted_as_operations():
    column = allow_for_column("REFERENCES", "reader")(Column("x", Integer))

    assert column_rules(column)[0].operation == "REFERENCES"


def test_columns_without_rules_report_none():
    assert column_rules(Column("x", Integer)) == []


def test_declaring_a_rule_makes_the_column_managed_for_that_role():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "managed_docs"
        id = Column(Integer, primary_key=True)
        secret = allow_for_column(PolicyCommands.SELECT, "app_reader")(Column(String(20)))

    column = Doc.__table__.c.secret
    assert column_is_managed("app_reader", column)
    assert not column_is_managed("someone_else", column)


def test_unmanaged_columns_are_left_alone():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "unmanaged_docs"
        id = Column(Integer, primary_key=True)

    assert not column_is_managed("anyone", Doc.__table__.c.id)


def test_manage_cls_for_combo_widens_ownership_to_a_whole_table():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "combo_docs"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    assert not column_is_managed("ops", Doc.__table__.c.id)

    manage_cls_for_combo(role="ops", table=Doc, column=All.All)

    assert column_is_managed("ops", Doc.__table__.c.id)
    assert not column_is_managed("other", Doc.__table__.c.id)


def test_manage_cls_for_combo_accepts_a_model_class():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "model_combo_docs"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    combo = manage_cls_for_combo(role="ops", table=Doc)

    assert combo == ("ops", "public", "model_combo_docs", All.All)


def test_manage_cls_for_combo_derives_table_and_schema_from_a_column():
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "col_combo_docs"
        __table_args__ = {"schema": "public"}
        id = Column(Integer, primary_key=True)

    combo = manage_cls_for_combo(role="ops", column=Doc.__table__.c.id)

    assert combo == ("ops", "public", "col_combo_docs", "id")


def test_column_info_is_used_so_migrations_still_render():
    """Unlike ``Table.info``, ``Column.info`` is not emitted into migrations."""
    Base = declarative_base()

    class Doc(Base):
        __tablename__ = "info_docs"
        id = Column(Integer, primary_key=True)
        secret = allow_for_column(PolicyCommands.SELECT, "reader")(Column(String(20)))

    assert Doc.__table__.info == {}
    assert "pgalchemy_cls" in Doc.__table__.c.secret.info
