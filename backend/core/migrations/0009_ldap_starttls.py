"""LDAP: StartTLS on ldap:// connections (on, as it always was)."""
from sqlalchemy import text

STEPS = (
    "ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ldap_starttls BOOLEAN NOT NULL DEFAULT true",
)


async def upgrade(conn):
    for step in STEPS:
        await conn.execute(text(step))
