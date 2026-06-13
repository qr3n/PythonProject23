"""add subscription_groups and group_id FK on provider_subscriptions

Revision ID: 0003_add_subscription_groups
Revises: 0002_address_filter_rules
Create Date: 2026-06-09 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_add_subscription_groups"
down_revision: Union[str, None] = "0002_address_filter_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create the parent table first
    op.create_table(
        "subscription_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_subscription_groups_name"),
    )

    # 2. Add nullable FK column on provider_subscriptions with SET NULL on delete
    op.add_column(
        "provider_subscriptions",
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_provider_subscriptions_group_id",
        "provider_subscriptions",
        ["group_id"],
    )
    op.create_foreign_key(
        "fk_provider_subscriptions_group_id",
        "provider_subscriptions",
        "subscription_groups",
        ["group_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_provider_subscriptions_group_id",
        "provider_subscriptions",
        type_="foreignkey",
    )
    op.drop_index(
        "ix_provider_subscriptions_group_id",
        table_name="provider_subscriptions",
    )
    op.drop_column("provider_subscriptions", "group_id")
    op.drop_table("subscription_groups")
