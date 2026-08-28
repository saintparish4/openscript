"""Create events table with append-only trigger.

Revision ID: 001
Revises:
Create Date: 2026-03-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("sequence_num", sa.Integer(), nullable=False),
    )
    op.create_index("ix_events_session_id", "events", ["session_id"])
    op.create_index("ix_events_session_sequence", "events", ["session_id", "sequence_num"])

    # Append-only enforcement: UPDATE and DELETE blocked at the DB level.
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_events_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'events table is append-only: % operations are not permitted',
                TG_OP;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute("""
        CREATE TRIGGER events_immutable
            BEFORE UPDATE OR DELETE ON events
            FOR EACH ROW
            EXECUTE FUNCTION prevent_events_mutation();
        """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS events_immutable ON events")
    op.execute("DROP FUNCTION IF EXISTS prevent_events_mutation()")
    op.drop_index("ix_events_session_sequence")
    op.drop_index("ix_events_session_id")
    op.drop_table("events")
