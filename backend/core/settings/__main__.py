"""
Root CLI for the settings the installer writes (no login: the first
superuser must set up the 2FA before the API accepts them):

    python -m core.settings agent-url [--if-empty] https://manager.example.com:8443

Run as the service user from the backend directory, like manager.pki.
"""
import argparse
import asyncio
import sys

from pydantic import ValidationError

from core.database import async_session_maker
from .models import SystemSettingsUpdate
from .router import get_system_settings


async def _agent_url(url: str, if_empty: bool) -> None:
    try:
        url = SystemSettingsUpdate(agent_url=url).agent_url
    except ValidationError as e:
        sys.exit(f"ERRORE: {e.errors()[0]['msg'].removeprefix('Value error, ')}")
    async with async_session_maker() as session:
        settings = await get_system_settings(session)
        if if_empty and settings.agent_url:
            print(f"URL agent già impostato: {settings.agent_url}")
            return
        settings.agent_url = url
        session.add(settings)
        await session.commit()
    print(f"URL agent: {url}")


def _main() -> None:
    parser = argparse.ArgumentParser(prog="python -m core.settings")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("agent-url")
    p.add_argument("--if-empty", action="store_true", help="only when not set yet (installer reruns)")
    p.add_argument("url")
    args = parser.parse_args()
    asyncio.run(_agent_url(args.url, args.if_empty))


if __name__ == "__main__":
    _main()
