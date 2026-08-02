"""SQL view declaration."""
import pytest
from sqlalchemy import Column, Integer, String, func, select
from sqlalchemy.orm import declarative_base

from pgalchemy import sql_view
from pgalchemy.registry import registry
from pgalchemy.views import View


@pytest.fixture()
def Model():
    Base = declarative_base()

    class Item(Base):
        __tablename__ = "items"
        id = Column(Integer, primary_key=True)
        label = Column(String(50))

    return Item


def test_decorator_returns_the_original_function(Model):
    @sql_view(schema="public")
    def item_labels():
        return select(Model.label)

    assert callable(item_labels)
    assert item_labels.__name__ == "item_labels"


def test_decorator_registers_a_view_named_after_the_function(Model):
    @sql_view(schema="reporting")
    def item_labels():
        return select(Model.label)

    declared = item_labels.__pgalchemy_view__
    assert declared in registry.views
    assert declared.name == "item_labels"
    assert declared.schema == "reporting"
    assert declared.materialized is False


def test_the_body_is_the_compiled_select(Model):
    @sql_view()
    def item_ids():
        return select(Model.id)

    body = item_ids.__pgalchemy_view__.definition_sql
    assert body.lower().startswith("select")
    assert "items" in body


def test_materialized_views_are_supported(Model):
    @sql_view(schema="public", materialized=True)
    def item_totals():
        return select(func.count(Model.id).label("n"))

    declared = item_totals.__pgalchemy_view__
    assert declared.materialized is True
    assert declared.create_sql().startswith("CREATE MATERIALIZED VIEW public.item_totals AS")


def test_schema_defaults_to_public(Model):
    @sql_view()
    def defaults():
        return select(Model.id)

    assert defaults.__pgalchemy_view__.schema == "public"


def test_view_from_a_sql_file_takes_its_name_from_the_path(tmp_path):
    (tmp_path / "my_view.sql").write_text("SELECT 1 AS n")

    declared = View(schema="test", path="my_view.sql", base_dir=tmp_path)

    assert declared.name == "my_view"
    assert declared.definition_sql == "SELECT 1 AS n"


def test_a_view_needs_a_body():
    with pytest.raises(ValueError, match="no body"):
        View(name="empty")


def test_a_view_needs_a_name_or_a_path():
    with pytest.raises(ValueError, match="name or a path"):
        View(sql="SELECT 1")


def test_to_entity_produces_the_right_alembic_utils_class(Model):
    plain = View(name="v_plain", sql="SELECT 1")
    materialized = View(name="v_mat", sql="SELECT 1", materialized=True)

    assert type(plain.to_entity()).__name__ == "PGView"
    assert type(materialized.to_entity()).__name__ == "PGMaterializedView"
