"""Time from which a user may approve other users' SSH keys."""
from sqlalchemy import text

STEPS = (
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS key_approval_after TIMESTAMP',
)


async def upgrade(conn):
    for step in STEPS:
        await conn.execute(text(step))
