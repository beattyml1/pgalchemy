"""Demo models exercising every pgalchemy feature.

Used by the integration tests and by ``alembic/env.py``. ``build_models()``
returns a fresh, independently-named set so a test can declare models without
colliding with another test's MetaData.
"""
from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.orm import declarative_base, relationship

from pgalchemy import (
    Policy,
    PolicyCommands,
    PolicyType,
    ReturnTypedExpression,
    allow_for_column,
    rls,
    rls_base,
    sql_function,
    sql_view,
)

CURRENT_USER = "current_setting('app.current_user_id')::integer"


def build_models(schema: str | None = None) -> SimpleNamespace:
    """Declare the demo schema and return everything it defines.

    ``schema=None`` means the connection's default schema. Pinning models to
    ``'public'`` explicitly makes Alembic see every table under two names once
    ``include_schemas`` is on, which shows up as endless foreign key churn.
    """
    table_args = {"schema": schema} if schema else {}

    def fk(target: str) -> str:
        return f"{schema}.{target}" if schema else target

    BaseModel = rls_base(declarative_base())
    PlainBase = declarative_base()

    class User(BaseModel):
        """RLS enabled by default, by virtue of the base class."""

        __tablename__ = "users"
        __table_args__ = table_args

        id = Column(Integer, primary_key=True)
        email = Column(String(255), unique=True, nullable=False)
        username = Column(String(100), unique=True, nullable=False)
        created_at = Column(DateTime, server_default=func.now())
        is_admin = allow_for_column(PolicyCommands.SELECT, "app_reader")(
            Column(Boolean, default=False)
        )

        posts = relationship("Post", back_populates="author")
        comments = relationship("Comment", back_populates="user")

    class Post(BaseModel):
        __tablename__ = "posts"
        __table_args__ = table_args

        id = Column(Integer, primary_key=True)
        title = Column(String(200), nullable=False)
        content = Column(Text)
        user_id = Column(Integer, ForeignKey(fk("users.id")), nullable=False)
        published = Column(Boolean, default=False)
        created_at = Column(DateTime, server_default=func.now())
        updated_at = Column(DateTime, onupdate=func.now())

        author = relationship("User", back_populates="posts")
        comments = relationship("Comment", back_populates="post")

    class Comment(BaseModel):
        __tablename__ = "comments"
        __table_args__ = table_args

        id = Column(Integer, primary_key=True)
        content = Column(Text, nullable=False)
        user_id = Column(Integer, ForeignKey(fk("users.id")), nullable=False)
        post_id = Column(Integer, ForeignKey(fk("posts.id")), nullable=False)
        created_at = Column(DateTime, server_default=func.now())

        user = relationship("User", back_populates="comments")
        post = relationship("Post", back_populates="comments")

    @rls(enabled=False)
    class PublicSetting(BaseModel):
        """Opts back out of the base class default."""

        __tablename__ = "public_settings"
        __table_args__ = table_args

        id = Column(Integer, primary_key=True)
        key = Column(String(100), nullable=False)
        value = Column(Text)

    @rls(enabled=True, force=True)
    class SecureDocument(PlainBase):
        """Decorator based RLS on a base that has none by default."""

        __tablename__ = "secure_documents"
        __table_args__ = table_args

        id = Column(Integer, primary_key=True)
        title = Column(String(200), nullable=False)
        content = Column(Text)
        owner_id = Column(Integer, ForeignKey(fk("users.id")), nullable=False)
        classification = Column(String(50), default="PUBLIC")
        created_at = Column(DateTime, server_default=func.now())

    policies = [
        Policy("users_select_policy", on=User, for_=PolicyCommands.SELECT, using="true"),
        Policy(
            "users_insert_policy",
            on=User,
            for_=PolicyCommands.INSERT,
            with_check="is_admin = false",
        ),
        Policy(
            "users_update_policy",
            on=User,
            for_=PolicyCommands.UPDATE,
            using=f"id = {CURRENT_USER}",
            with_check=f"id = {CURRENT_USER}",
        ),
        Policy(
            "users_delete_policy",
            on=User,
            as_=PolicyType.RESTRICTIVE,
            for_=PolicyCommands.DELETE,
            using="is_admin = true",
        ),
        Policy(
            "posts_select_public", on=Post, for_=PolicyCommands.SELECT, using="published = true"
        ),
        Policy(
            "posts_modify_own",
            on=Post,
            for_=PolicyCommands.ALL,
            using=f"user_id = {CURRENT_USER}",
            with_check=f"user_id = {CURRENT_USER}",
        ),
        Policy(
            "comments_select_policy", on=Comment, for_=PolicyCommands.SELECT, using="true"
        ),
        Policy(
            "comments_modify_own",
            on=Comment,
            for_=PolicyCommands.ALL,
            using=f"user_id = {CURRENT_USER}",
            with_check=f"user_id = {CURRENT_USER}",
        ),
        Policy(
            "secure_docs_select_policy",
            on=SecureDocument,
            for_=PolicyCommands.SELECT,
            using=f"owner_id = {CURRENT_USER} OR classification = 'PUBLIC'",
        ),
        Policy(
            "secure_docs_all_owner",
            on=SecureDocument,
            for_=PolicyCommands.ALL,
            using=f"owner_id = {CURRENT_USER}",
            with_check=f"owner_id = {CURRENT_USER}",
        ),
    ]

    @sql_function(schema=schema)
    def post_count(user_id: int) -> int:
        return ReturnTypedExpression[int](
            select(func.count(Post.id)).where(Post.user_id == user_id)
        )

    @sql_view(schema=schema)
    def published_posts():
        return select(Post.id, Post.title, Post.user_id).where(Post.published.is_(True))

    metadata = MetaData()
    for table in list(BaseModel.metadata.tables.values()) + list(
        PlainBase.metadata.tables.values()
    ):
        table.to_metadata(metadata)

    return SimpleNamespace(
        BaseModel=BaseModel,
        PlainBase=PlainBase,
        User=User,
        Post=Post,
        Comment=Comment,
        PublicSetting=PublicSetting,
        SecureDocument=SecureDocument,
        policies=policies,
        post_count=post_count,
        published_posts=published_posts,
        metadata=metadata,
        schema=schema,
    )


#: Module level instance for ``alembic/env.py``.
demo = build_models()
BaseModel = demo.BaseModel
PlainBase = demo.PlainBase
target_metadata = demo.metadata
