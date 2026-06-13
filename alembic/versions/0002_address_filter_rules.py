"""add address_filter_rules

Revision ID: 0002_address_filter_rules
Revises: 0001_initial
Create Date: 2026-06-08 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_address_filter_rules"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # DO-блок: истинно идемпотентное создание типа.
    # Если тип уже есть (остаток упавшего прогона) — молча пропускаем.
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE filter_action AS ENUM ('block', 'allow');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)

    op.create_table(
        "address_filter_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column(
            "action",
            # postgresql.ENUM вместо sa.Enum — только у него create_type=False
            # реально проверяется в методе create() перед эмитом DDL
            postgresql.ENUM("block", "allow", name="filter_action", create_type=False),
            nullable=False,
            server_default="block",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_address_filter_rules_is_active",
        "address_filter_rules",
        ["is_active"],
    )


def downgrade() -> None:
    op.drop_index("ix_address_filter_rules_is_active", table_name="address_filter_rules")
    op.drop_table("address_filter_rules")
    op.execute("DROP TYPE IF EXISTS filter_action")