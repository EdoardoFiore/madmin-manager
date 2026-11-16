#!/bin/bash
# =================================================================
#                MADMIN Manager - Restore of the manager
# =================================================================
# Restores an archive of manager-backup.sh onto a manager installed with
# setup-manager.sh (same --host/--ip as the old one, so the instances find it
# and the endpoint certificate in the archive matches). Replaces the database,
# DATA_DIR and SECRET_KEY; the database password of this installation is kept.
#
# Usage:
#   sudo bash manager-restore.sh --in /root/manager.bak --passphrase-file /root/pass [-y]
#
# The instances reconnect by themselves (same CA, same address). A manager
# restored on a different address needs a new endpoint certificate
# (python -m manager.pki server-cert --host ...) and the instances must be
# told the new address before the old manager goes away (Sposta manager).
# =================================================================
set -euo pipefail
umask 077

IN=""; PASS_FILE=""; YES="false"
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --in) IN="$2"; shift ;;
        --passphrase-file) PASS_FILE="$2"; shift ;;
        -y) YES="true" ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[ -f "$IN" ] && [ -s "$PASS_FILE" ] || { echo "--in <archive> and --passphrase-file required" >&2; exit 1; }

INSTALL_DIR="/opt/madmin-manager"
DATA_DIR="$INSTALL_DIR/data"
SERVICE_USER="madmin-manager"
DB_NAME="madmin_manager"
DB_USER="madmin_manager"
ENV_FILE="$INSTALL_DIR/backend/.env"
[ -f "$ENV_FILE" ] || { echo "Install the manager first (setup-manager.sh)" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Archives of manager-backup.sh 1.4.0+ start with "MMBK2 <hmac>": checked
# (wrong passphrase or altered file) before anything is decrypted or unpacked
OFFSET="$(python3 - "$PASS_FILE" "$IN" << 'PY'
import hashlib, hmac, sys
with open(sys.argv[2], "rb") as f:
    head = f.read(6)
    if head != b"MMBK2 ":
        print(0)
        sys.exit(0)
    expected = f.readline().strip().decode()
    offset = 6 + len(expected) + 1
    passphrase = open(sys.argv[1], "rb").read().split(b"\n")[0]
    key = hashlib.pbkdf2_hmac("sha256", passphrase, b"madmin-manager backup mac v1", 200000)
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for chunk in iter(lambda: f.read(1 << 20), b""):
        mac.update(chunk)
if not hmac.compare_digest(mac.hexdigest(), expected):
    sys.exit("Archive check failed: wrong passphrase, or the file was altered")
print(offset)
PY
)"
if [ "$OFFSET" = "0" ]; then
    echo "WARNING: archive without integrity check (made by manager-backup.sh before 1.4.0)" >&2
fi
tail -c +"$((OFFSET + 1))" "$IN" \
    | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$PASS_FILE" | tar -C "$WORK" -xzf -
B="$WORK/backup"
for f in database.dump env data.tar info.json; do
    [ -f "$B/$f" ] || { echo "Archive incomplete: $f missing" >&2; exit 1; }
done
echo "Archive: $(tr -d '\n' < "$B/info.json")"

if [ "$YES" != "true" ]; then
    read -r -p "Replace the database, the PKI and the backups of this manager? [y/N] " ans
    [[ "$ans" =~ ^[yY]$ ]] || exit 0
fi

systemctl stop madmin-manager.service

# Into a staging database first: the current one is dropped only when the
# restore succeeded
STAGE="${DB_NAME}_restore"
sudo -u postgres psql -qc "DROP DATABASE IF EXISTS $STAGE;"
sudo -u postgres psql -qc "CREATE DATABASE $STAGE OWNER $DB_USER;"
if ! sudo -u postgres pg_restore --exit-on-error --no-owner --role="$DB_USER" -d "$STAGE" < "$B/database.dump"; then
    sudo -u postgres psql -qc "DROP DATABASE IF EXISTS $STAGE;"
    systemctl start madmin-manager.service
    echo "Database restore failed: nothing changed" >&2
    exit 1
fi
sudo -u postgres psql -qc "DROP DATABASE $DB_NAME;"
sudo -u postgres psql -qc "ALTER DATABASE $STAGE RENAME TO $DB_NAME;"

# DATA_DIR: the old one is kept aside until the end
OLD_DATA="$DATA_DIR.before-restore.$(date +%s)"
mv "$DATA_DIR" "$OLD_DATA"
mkdir -p "$DATA_DIR"
tar -C "$DATA_DIR" -xf "$B/data.tar"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR"

# SECRET_KEY from the archive (it decrypts the PKI and the passphrases)
SECRET_KEY="$(sed -n 's/^SECRET_KEY=//p' "$B/env")"
[ -n "$SECRET_KEY" ] || { echo "SECRET_KEY missing in the archive" >&2; exit 1; }
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$ENV_FILE"

cd "$INSTALL_DIR/backend"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -m manager.pki trust-bundle
# An archive older than 1.6.0 has no ui-tls/, which nginx reads the UI certificate from
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -m manager.uicert ensure
cd - >/dev/null
# DATA_DIR was replaced: watch the new directory
systemctl try-restart madmin-manager-nginx-reload.path 2>/dev/null || true
nginx -t && systemctl reload nginx
systemctl start madmin-manager.service

for _ in $(seq 1 60); do
    if curl -sf -o /dev/null http://127.0.0.1:8000/api/health; then
        rm -rf "$OLD_DATA"
        echo "Restore done. CA fingerprint: $(cd "$INSTALL_DIR/backend" && sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -m manager.pki fingerprint)"
        exit 0
    fi
    sleep 2
done
echo "The manager did not start after the restore (journalctl -u madmin-manager -e). Old DATA_DIR: $OLD_DATA" >&2
exit 1
