"""
Manager settings API.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from core.auth.dependencies import get_current_user, require_permission
from core.auth.models import User
from core.database import get_session

from .models import SystemSettings, SystemSettingsUpdate

router = APIRouter(prefix="/api/settings", tags=["Settings"])

# Fields every logged-in user may read (branding, language)
_PUBLIC = ("company_name", "primary_color", "default_language")


async def get_system_settings(session: AsyncSession) -> SystemSettings:
    row = (await session.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    if row is None:
        row = SystemSettings(id=1)
        session.add(row)
        await session.flush()
    return row


@router.get("/system")
async def read_settings(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    row = await get_system_settings(session)
    data = row.model_dump(exclude={"smtp_password", "ldap_bind_password"})
    data["smtp_password_set"] = bool(row.smtp_password)
    data["ldap_bind_password_set"] = bool(row.ldap_bind_password)
    if not current_user.has_permission("manager.view"):
        data = {k: data[k] for k in _PUBLIC}
    return data


@router.patch("/system")
async def update_settings(
    body: SystemSettingsUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission("manager.manage")),
):
    row = await get_system_settings(session)
    changes = body.model_dump(exclude_unset=True)
    from core.secrets import encrypt_setting
    for secret in ("smtp_password", "ldap_bind_password"):
        value = changes.pop(secret, None)
        if value:
            setattr(row, secret, encrypt_setting(value))
    for key, value in changes.items():
        if value is not None:
            setattr(row, key, value)
    if row.support_port_min > row.support_port_max:
        raise HTTPException(400, "Intervallo porte di supporto non valido")
    if row.support_port_max - row.support_port_min > 200:
        raise HTTPException(400, "Al massimo 200 porte di supporto")
    row.updated_at = datetime.utcnow().isoformat()
    session.add(row)
    await session.commit()
    if {"autoupdate_time", "autoupdate_tz", "autoupdate_randomize"} & set(changes):
        from manager.osactions.service import reconcile_all
        await reconcile_all(session)
    data = row.model_dump(exclude={"smtp_password", "ldap_bind_password"})
    data["smtp_password_set"] = bool(row.smtp_password)
    data["ldap_bind_password_set"] = bool(row.ldap_bind_password)
    return data


@router.post("/smtp/test")
async def smtp_test(session: AsyncSession = Depends(get_session),
                    current_user: User = Depends(require_permission("manager.manage"))):
    """A test e-mail to the notification recipients."""
    from manager.notify import recipients, send
    row = await get_system_settings(session)
    if not row.smtp_host:
        raise HTTPException(400, "Server SMTP non configurato")
    to = await recipients(session, row)
    if not to:
        raise HTTPException(400, "Nessun destinatario: indicare notify_to o un'e-mail sui superuser")
    errors = await send(row, "Prova di notifica", f"E-mail di prova inviata da {current_user.username}.", to)
    if errors:
        raise HTTPException(502, "; ".join(errors)[:500])
    return {"sent_to": to}


class UICertificateUpload(BaseModel):
    cert_pem: str = Field(min_length=1, max_length=40000)   # may hold the chain too
    key_pem: str = Field(min_length=1, max_length=20000)
    chain_pem: str = Field(default="", max_length=60000)
    # Host the operator is using the UI with: a certificate not valid for it
    # is refused unless forced
    host: str = Field(default="", max_length=255)
    force: bool = False
    totp: str = Field(default="", max_length=16)


@router.get("/ui-certificate")
async def ui_certificate(current_user: User = Depends(require_permission("manager.view"))):
    """The certificate nginx serves on the UI port (never the agent endpoint's)."""
    from manager import pki, uicert
    out = uicert.info()
    try:
        # The endpoint certificate renews by itself, the CA does not (rotate-ca)
        out.update(pki.expiry())
    except (pki.PKIError, ValueError):
        pass
    return out


@router.post("/ui-certificate")
async def ui_certificate_install(body: UICertificateUpload, request: Request,
                                 session: AsyncSession = Depends(get_session),
                                 current_user: User = Depends(require_permission("manager.manage"))):
    """Whoever holds the key of the installed certificate can pass for the UI
    to the operators: a fresh 2FA code, asked once the files are known good
    (a code is accepted once)."""
    from core.auth.router import require_step_up
    from manager import uicert
    try:
        state = uicert.prepare(body.cert_pem, body.key_pem, body.chain_pem, body.host, body.force)
        await require_step_up(session, current_user, body.totp, request)
        return await uicert.apply(state)
    except uicert.UICertReloadError as e:
        raise HTTPException(503, str(e))
    except uicert.UICertError as e:
        raise HTTPException(400, str(e))


@router.delete("/ui-certificate")
async def ui_certificate_reset(current_user: User = Depends(require_permission("manager.manage"))):
    """Back to the internal certificate (issued by the agent CA)."""
    from manager import uicert
    try:
        return await uicert.reset()
    except uicert.UICertError as e:
        raise HTTPException(503, str(e))


class LdapSearch(BaseModel):
    query: str = Field(min_length=2, max_length=100)


@router.post("/ldap/search")
async def ldap_search(body: LdapSearch, session: AsyncSession = Depends(get_session),
                      current_user: User = Depends(require_permission("manager.manage"))):
    """Users and groups of the directory to build the access rules from
    (the saved connection; names only, no passwords)."""
    import asyncio
    from manager.ldapauth import LdapError, search
    row = await get_system_settings(session)
    try:
        return await asyncio.to_thread(search, row, body.query)
    except (LdapError, ValueError) as e:
        raise HTTPException(400, f"LDAP: {e}")


class LdapTest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=500)


@router.post("/ldap/test")
async def ldap_test(body: LdapTest, session: AsyncSession = Depends(get_session),
                    current_user: User = Depends(require_permission("manager.manage"))):
    """What a login of this user would get (nothing is created)."""
    import asyncio
    from manager.ldapauth import LdapError, check
    row = await get_system_settings(session)
    try:
        return await asyncio.to_thread(check, row, body.username, body.password)
    except (LdapError, ValueError) as e:
        raise HTTPException(400, f"LDAP: {e}")
