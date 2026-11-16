"""
Certificate of the UI (nginx, operators' port), separate from the one of the
agent endpoint.

DATA_DIR/ui-tls/ (0700):

    cert.pem / key.pem   what nginx serves on the UI port. Symlinks to
                         ../pki/server.pem and ../pki/server.key by default (the
                         certificate issued by the agent CA: browsers do not know
                         it); regular files once a certificate is installed from
                         Settings (leaf first, then its intermediates).
    reload               written to ask for an nginx reload.

The service cannot reload nginx (unprivileged, ProtectSystem=strict). The
installer adds madmin-manager-nginx-reload.path, which watches `reload` and
runs `nginx -t && systemctl reload nginx` as root. Whether nginx took the
change is read from the UI port itself: the certificate it presents. If it
does not show up, the previous files are put back.

The agent endpoint (:8443) never reads this directory: the instances trust
the agent CA only, a public certificate there would cut all of them off.

    python -m manager.uicert ensure   (create the default links when missing)
    python -m manager.uicert reset    (back to the internal certificate; then reload nginx)
"""
import asyncio
import hashlib
import ipaddress
import os
import secrets as pysecrets
import ssl
import tempfile
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from config import get_settings

DEFAULT_CERT = os.path.join("..", "pki", "server.pem")
DEFAULT_KEY = os.path.join("..", "pki", "server.key")
RELOAD_WAIT = 15      # seconds for nginx to present the new certificate
RELOAD_RETRY = 5      # the request is written again: a path unit can miss one
MAX_CHAIN = 8

# None = the internal certificate (the two symlinks); else (cert.pem, key.pem)
State = Optional[Tuple[bytes, bytes]]

_lock = asyncio.Lock()


class UICertError(Exception):
    """The certificate, key or chain given is not usable."""


class UICertReloadError(UICertError):
    """nginx did not take the change (the previous certificate is back)."""


def ui_dir() -> str:
    return os.path.join(get_settings().data_dir, "ui-tls")


def _p(name: str) -> str:
    return os.path.join(ui_dir(), name)


def _read(name: str) -> bytes:
    with open(_p(name), "rb") as f:
        return f.read()


def _write(name: str, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=ui_dir(), prefix=f".{name}.")
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)
    os.replace(tmp, _p(name))


def _link(name: str, target: str) -> None:
    tmp = _p(f".{name}.{pysecrets.token_hex(4)}")
    os.symlink(target, tmp)
    os.replace(tmp, _p(name))


def is_installed() -> bool:
    """The installer set the directory up (nginx reads from it)."""
    return os.path.lexists(_p("cert.pem")) and os.path.lexists(_p("key.pem"))


def is_custom() -> bool:
    return os.path.lexists(_p("cert.pem")) and not os.path.islink(_p("cert.pem"))


def _snapshot() -> State:
    return (_read("cert.pem"), _read("key.pem")) if is_custom() else None


def _write_state(state: State) -> None:
    os.makedirs(ui_dir(), mode=0o700, exist_ok=True)
    # Key first: between the two writes nginx is not reloaded by anyone else
    if state is None:
        _link("key.pem", DEFAULT_KEY)
        _link("cert.pem", DEFAULT_CERT)
    else:
        _write("key.pem", state[1])
        _write("cert.pem", state[0])


def ensure() -> None:
    """Default links when the directory is new or incomplete (installer, restore)."""
    os.makedirs(ui_dir(), mode=0o700, exist_ok=True)
    if not is_installed():
        _write_state(None)
    if not os.path.exists(_p("reload")):
        _write("reload", b"")


# --- Reading certificates ---

def _fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _cn(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cn[0].value) if cn else name.rfc4514_string()


def _names(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [str(cn[0].value)] if cn else []
    return san.get_values_for_type(x509.DNSName) + [str(a) for a in san.get_values_for_type(x509.IPAddress)]


def covers(names: List[str], host: str) -> bool:
    """Whether a certificate with these names is valid for the host (one-label wildcards)."""
    host = host.strip("[]").lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for name in names:
        name = name.lower()
        if ip is not None:
            try:
                if ipaddress.ip_address(name) == ip:
                    return True
            except ValueError:
                pass
        elif name == host or (name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]):
            return True
    return False


def info() -> dict:
    out = {"installed": is_installed(), "custom": is_custom()}
    try:
        certs = x509.load_pem_x509_certificates(_read("cert.pem"))
    except (OSError, ValueError):
        return out
    leaf = certs[0]
    out.update(
        subject=_cn(leaf.subject),
        issuer=_cn(leaf.issuer),
        names=_names(leaf),
        not_before=leaf.not_valid_before_utc.isoformat(),
        not_after=leaf.not_valid_after_utc.isoformat(),
        days_left=(leaf.not_valid_after_utc - datetime.now(timezone.utc)).days,
        fingerprint=_fp(leaf),
        chain=len(certs) - 1,
    )
    return out


def _current_fp() -> str:
    return _fp(x509.load_pem_x509_certificates(_read("cert.pem"))[0])


# --- Checking what an operator uploads ---

def _load_certs(pem: str, what: str) -> List[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem.encode())
    except ValueError:
        raise UICertError(f"{what}: non è un certificato PEM (-----BEGIN CERTIFICATE-----)")


def build(cert_pem: str, key_pem: str, chain_pem: str = "") -> Tuple[bytes, bytes, x509.Certificate]:
    """cert.pem (leaf, then its intermediates in order), key.pem and the leaf."""
    certs = _load_certs(cert_pem, "Certificato")
    leaf = certs[0]
    pool = certs[1:] + (_load_certs(chain_pem, "CA bundle") if chain_pem.strip() else [])

    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except TypeError:
        raise UICertError("La chiave privata è protetta da password: toglierla prima "
                          "(openssl pkey -in chiave.key -out chiave-senza-password.key)")
    except ValueError:
        raise UICertError("Chiave privata: non è una chiave PEM (-----BEGIN PRIVATE KEY-----)")
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise UICertError("Chiave privata: sono ammesse RSA ed ECDSA")
    spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(*spki) != leaf.public_key().public_bytes(*spki):
        raise UICertError("La chiave privata non corrisponde al certificato")

    now = datetime.now(timezone.utc)
    if leaf.not_valid_after_utc <= now:
        raise UICertError(f"Certificato scaduto il {leaf.not_valid_after_utc:%d/%m/%Y}")
    if leaf.not_valid_before_utc > now:
        raise UICertError(f"Certificato non ancora valido (dal {leaf.not_valid_before_utc:%d/%m/%Y})")

    # Intermediates in the order nginx must send them, whatever the order of
    # the files. The root is left out: browsers have their own.
    chain: List[x509.Certificate] = []
    current = leaf
    while current.subject != current.issuer and len(chain) < MAX_CHAIN:
        issuer = next((c for c in pool if c.subject == current.issuer and c not in chain and c != leaf), None)
        if issuer is None:
            break
        if issuer.subject != issuer.issuer:
            chain.append(issuer)
        current = issuer
    if pool and not chain and not any(c.subject == leaf.issuer for c in pool):
        raise UICertError(f"Il CA bundle non contiene chi ha emesso il certificato ({_cn(leaf.issuer)})")

    cert_out = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [leaf] + chain)
    key_out = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert_out, key_out, leaf


# --- Applying a change ---

async def _served() -> Optional[str]:
    """sha256 of the certificate nginx presents on the UI port right now."""
    # Not a trust decision: the certificate is only compared with the one just
    # written, so it is read without verification (it may be self-signed).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", get_settings().ui_port, ssl=ctx), 3)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
    return hashlib.sha256(der).hexdigest() if der else None


def request_reload() -> None:
    _write("reload", f"{time.time()}\n".encode())


async def _reload(expected: str) -> bool:
    deadline = time.monotonic() + RELOAD_WAIT
    asked = None
    while time.monotonic() < deadline:
        if asked is None or time.monotonic() - asked >= RELOAD_RETRY:
            request_reload()
            asked = time.monotonic()
        await asyncio.sleep(0.5)
        if await _served() == expected:
            return True
    return False


async def apply(state: State) -> dict:
    """Write the state (None = the internal certificate), reload nginx, check."""
    if not is_installed():
        raise UICertReloadError("Certificato della UI non gestito da questa installazione: "
                                "rieseguire setup-manager.sh di questa versione")
    async with _lock:
        previous = _snapshot()
        _write_state(state)
        try:
            ok = await _reload(_current_fp())
        except Exception:
            ok = False
        if not ok:
            _write_state(previous)
            request_reload()
            raise UICertReloadError(
                f"nginx non ha caricato il certificato entro {RELOAD_WAIT} secondi: è stato rimesso il precedente "
                "(sul manager: systemctl status madmin-manager-nginx-reload.service)")
        return info()


def prepare(cert_pem: str, key_pem: str, chain_pem: str = "", host: str = "", force: bool = False) -> State:
    """The checked files to hand to apply(). `host`: the name the operator is
    using the UI with; a certificate not valid for it is refused unless forced."""
    cert, key, leaf = build(cert_pem, key_pem, chain_pem)
    names = _names(leaf)
    if host and not force and not covers(names, host):
        raise UICertError(f"Il certificato non vale per {host} (vale per: {', '.join(names) or 'nessun nome'})")
    return cert, key


async def reset() -> dict:
    return await apply(None)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="python -m manager.uicert")
    parser.add_argument("action", choices=("ensure", "reset"))
    args = parser.parse_args()
    if args.action == "ensure":
        ensure()
    else:
        _write_state(None)
        print("Certificato della UI: di nuovo quello interno. Ora: nginx -t && systemctl reload nginx")
