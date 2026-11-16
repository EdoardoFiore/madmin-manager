"""
Daily look at the certificates nginx serves (manager.pki, manager.uicert):

- the certificate of the agent endpoint is re-issued when it has less than
  pki.SERVER_RENEW_DAYS left, with the names it has and the same CA. The
  instances pin the CA, not this certificate: nothing changes for them;
- nginx is made to load it: what the agent port presents is compared with the
  file, and a reload is asked for while they differ (also after a manual
  `pki server-cert` nobody reloaded nginx for). An e-mail if it does not take;
- what does not renew by itself gets an e-mail near its end: the CA (rotate-ca,
  see pki.py) and a certificate of the UI installed from Settings.
"""
import asyncio
import logging

from config import get_settings
from manager import pki, uicert
from manager.notify import notify

logger = logging.getLogger("madmin_manager.certwatch")

INTERVAL = 24 * 3600
# Days left at which an e-mail goes out (the check is daily)
CA_WARN = (365, 180, 90, 60)   # and every day under 30
UI_WARN = (30, 14, 7, 3, 1)    # and every day once expired


async def check_once() -> None:
    if pki.renew_server_cert_if_due():
        logger.info("Agent endpoint certificate re-issued (less than %d days left)", pki.SERVER_RENEW_DAYS)

    expected = pki.server_cert_fingerprint()
    port = get_settings().agent_port
    if await uicert.served(port) != expected:
        if await uicert.reload(expected, port):
            logger.info("nginx loaded the agent endpoint certificate")
        else:
            logger.error("nginx does not present the current agent endpoint certificate on port %d", port)
            notify("certificate", "endpoint-reload", "Certificato della porta delle istanze non caricato da nginx",
                   f"Il certificato della porta delle istanze ({port}) su disco non è quello che nginx presenta, "
                   "e la richiesta di ricarica non ha avuto effetto. Sul manager: nginx -t && systemctl reload nginx "
                   "(e systemctl status madmin-manager-nginx-reload.path). Finché nginx presenta quello vecchio, "
                   "alla sua scadenza le istanze non si collegano più.")

    ca = pki.expiry()["ca"]
    if ca["days_left"] in CA_WARN or ca["days_left"] < 30:
        notify("certificate", "ca-expiry", f"La CA del manager scade tra {ca['days_left']} giorni",
               f"La CA che firma i certificati delle istanze scade il {ca['not_after'][:10]}. Non si rinnova da sola: "
               "va ruotata prima (python -m manager.pki rotate-ca prepare, poi activate e retire: docs/PROTOCOL.md). "
               "Alla scadenza nessuna istanza si collega più.")

    ui = uicert.info()
    days = ui.get("days_left")
    if ui.get("custom") and days is not None and (days in UI_WARN or days <= 0):
        when = f"scade tra {days} giorni" if days > 0 else "è scaduto"
        notify("certificate", "ui-expiry", f"Il certificato della UI {when}",
               f"Il certificato della UI ({', '.join(ui.get('names') or [])}) {when} ({ui['not_after'][:10]}). "
               "Non si rinnova da solo: caricare il nuovo in Impostazioni > Certificato della UI.")


async def watch_task() -> None:
    while True:
        try:
            await check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Certificate check error")
        await asyncio.sleep(INTERVAL)
