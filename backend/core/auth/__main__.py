"""
Root CLI for the accounts, for when no other superuser can help (the only
superuser lost the authenticator, or the 2FA is locked):

    python -m core.auth reset-2fa <username>

The 2FA is cleared and every session closed: the next login asks to set it
up again. Run as the service user from the backend directory, like manager.pki.
"""
import argparse
import asyncio
import sys
from datetime import datetime, timezone

import manager.models  # noqa: F401  the user table's foreign keys point at manager tables
from core.audit.models import AuditLog
from core.database import async_session_maker
from . import service


async def _reset_2fa(username: str) -> None:
    async with async_session_maker() as session:
        user = await service.get_user_by_username(session, username)
        if user is None:
            sys.exit(f"ERRORE: utente {username} non trovato")
        user.totp_enabled = False
        user.totp_locked = False
        user.totp_secret = None
        user.backup_codes = None
        service.revoke_sessions(user)
        session.add(user)
        session.add(AuditLog(timestamp=datetime.now(timezone.utc).replace(tzinfo=None), username="root-cli",
                             method="CLI", path=f"core.auth reset-2fa {username}", status_code=200,
                             duration_ms=0, category="write"))
        await session.commit()
    print(f"2FA di {username} azzerata: al prossimo accesso va configurata di nuovo")
    from manager.notify import _deliver
    await _deliver(f"2FA di {username} azzerata dalla CLI root",
                   f"La 2FA dell'utente {username} è stata azzerata dalla CLI root del manager "
                   "(python -m core.auth reset-2fa): al prossimo accesso la configura di nuovo.", superusers=True)


def _main() -> None:
    parser = argparse.ArgumentParser(prog="python -m core.auth")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reset-2fa")
    p.add_argument("username")
    args = parser.parse_args()
    asyncio.run(_reset_2fa(args.username))


if __name__ == "__main__":
    _main()
