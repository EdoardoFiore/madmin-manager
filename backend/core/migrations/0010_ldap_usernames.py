"""LDAP users: who disabled a user (disabled_by), and usernames in lower case.

The directory ignores case, the manager did not: "MRossi" and "mrossi" could
be two users. An LDAP username is now the directory's login name in lower
case. Existing ones are lowered; where two of them differ only by case, the
ones not already in lower case are disabled (and their sessions revoked),
data kept: the lower-case one, or the user created at the next login, is
the account.
"""
from sqlalchemy import text

STEPS = (
    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS disabled_by VARCHAR(10) NOT NULL DEFAULT ''",
    # Duplicates by case: disabled, not renamed
    """UPDATE "user" u SET is_active = false, disabled_by = '', tokens_valid_after = now() AT TIME ZONE 'utc'
       WHERE u.auth_source = 'ldap' AND u.username <> lower(u.username)
         AND EXISTS (SELECT 1 FROM "user" o WHERE o.id <> u.id AND lower(o.username) = lower(u.username))""",
    """UPDATE "user" u SET username = lower(u.username)
       WHERE u.auth_source = 'ldap' AND u.username <> lower(u.username)
         AND NOT EXISTS (SELECT 1 FROM "user" o WHERE o.id <> u.id AND lower(o.username) = lower(u.username))""",
)


async def upgrade(conn):
    for step in STEPS:
        await conn.execute(text(step))
