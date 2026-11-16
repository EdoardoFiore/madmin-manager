# Operations

How to run a MADMIN Manager and its instances day to day. The wire protocol is in `PROTOCOL.md`, the plan in `ROADMAP.md`, how a release is built in the MADMIN repository (`docs/RELEASING.md`).

## 1. Manager

### Install

```bash
sudo MADMIN_MANAGER_ADMIN_PASSWORD='...' bash scripts/setup-manager.sh --host manager.example.com \
     [--ip 10.0.0.5] -u <admin> --ui-allow 10.0.0.0/24,192.0.2.10
```

- `--host/--ip`: what instances use to reach the manager (in the endpoint certificate and in every token).
- `--ui-allow`: source addresses allowed on the UI (nginx, `/etc/nginx/snippets/madmin-manager-ui-allow.conf`). Required in production: a first install refuses to start without it, unless `--ui-allow-any` (a test manager open to every address). To change it later: rerun with `--ui-allow`, or edit the file and `nginx -t && systemctl reload nginx`. The agent port stays open to the instances.
- Rerunning the installer over an existing manager keeps database, `SECRET_KEY` and PKI: it is how the manager is updated. Schema steps run at startup (`backend/core/migrations/`) and go forward only, so take a backup first:

  ```bash
  sudo bash scripts/manager-backup.sh --out /root/manager-$(date +%F).bak --passphrase-file /root/pass
  git pull --ff-only
  sudo bash scripts/setup-manager.sh
  ```

  A rerun needs no password (only when no user exists yet) and no options: it keeps the UI filter and reissues the endpoint certificate with its current names. Given `--host`/`--ip` must include every current name (enrolled instances may use any of them); `--replace-names` drops one on purpose.

Open towards the manager: UI port (operators, filtered), agent port 8443 (instances), support ports 9100–9119 (operators; each session admits one IP).

### Certificates

Two certificates, never mixed:

- **Agent port (8443)**: issued by the manager CA for `--host/--ip` (`DATA_DIR/pki/server.pem`, 825 days). The instances trust that CA only: never put another certificate there. It renews by itself: under 60 days left the service re-issues it (same names, same CA, nothing changes for the instances) and has nginx reloaded; an e-mail goes out if nginx does not take it. By hand: rerun the installer, or `python -m manager.pki server-cert --host ... [--ip ...]` as `madmin-manager` in `backend/` (nginx is reloaded at the next daily check, or `systemctl reload nginx`).
- **Manager CA** (10 years): does not renew by itself. E-mails at 365, 180, 90, 60 days and daily under 30; Settings shows its end. Rotate it with `python -m manager.pki rotate-ca` (`PROTOCOL.md`).
- **UI port**: the same certificate by default, so browsers warn. Settings → Certificato della UI installs your own (certificate, key without password, optional CA bundle; PEM; your 2FA code). nginx is reloaded and asked for the certificate it presents: if it is not the new one, the previous comes back. It does not renew by itself: upload the new one before the expiry shown there (e-mails at 30, 14, 7, 3, 1 days). A reinstall and a restore keep it.

If a certificate locks you out of the UI: `cd /opt/madmin-manager/backend && sudo -u madmin-manager ../venv/bin/python -m manager.uicert reset && nginx -t && systemctl reload nginx`.

### Backup and restore

```bash
# backup (encrypted with the passphrase file; store it offline with the passphrase)
sudo bash scripts/manager-backup.sh --out /root/manager-$(date +%F).bak --passphrase-file /root/pass [--no-instance-backups]
# restore onto a manager installed with setup-manager.sh (same --host/--ip)
sudo bash scripts/manager-restore.sh --in /root/manager.bak --passphrase-file /root/pass
```

The archive holds the database, `DATA_DIR` (CA keys, release files, instance backups) and `SECRET_KEY`: whoever has it and the passphrase controls every instance. The instances reconnect by themselves after a restore (same CA, same address). Losing `SECRET_KEY` makes the PKI and the backup passphrases unreadable: keep a backup offline.

### Users

- Superusers only: support, enrollment, releases, updates and OS actions, rollouts of those, settings, logs. Every superuser should have TOTP (support needs it).
- LDAP/AD (Settings → LDAP / Active Directory): access rules, one per user or per directory group, each with role, access (read-write or read-only) and manager group; nobody without a rule enters. A rule for the user wins over the group rules. "Cerca nella directory" finds users and groups under a folder (a DN inside the search base) by name, or lists the whole folder; tick the ones to add and give them role, access and manager group. Test with "Prova un login" before enabling. The directory's certificate is verified: it must match the host name in the URL (use a DNS name, not an IP) and its CA goes in the CA field unless it is a public one. For a self-signed certificate or an IP, "Verifica il certificato del server" can be turned off: still encrypted, but the server is not authenticated. Keep at least one local superuser.

## 2. Instances

### Install and enroll

On the new VM (Ubuntu 24.04), as root, with a token from Enrollment (or `POST /api/provisioning/tokens`):

```bash
MADMIN_ADMIN_PASSWORD='...' bash scripts/setup-madmin.sh -u admin --manager-token-file /root/token
```

A reinstall keeps the instance's identity with a re-enroll token (instance page → Token re-enroll), then restore its last backup from the manager. **A reinstall over SSH loses the SSH access until the backup is restored**: the fresh firewall admits no new inbound connection. Run it from the console, or rely on the restore through the manager (the instance connects outbound).

### Releases and updates

1. Build on an Ubuntu 24.04 machine: `bash scripts/build-release.sh` (a critical OSV advisory in the wheels stops it; see `scripts/osv-waivers.txt`).
2. Sign on the offline machine: `bash scripts/sign-release.sh dist/<file>.unsigned.tar <key.pem>`.
3. Upload in Release (candidate). Try it on one instance (instance page → Aggiorna).
4. Promote to stable, then a rollout (below).

A failed update rolls back by itself (release, database, units). The instance page shows the journal and the log tail; an e-mail goes to the superusers.

### Rollouts

Rollout → Nuovo rollout: action (MADMIN update, package upgrade, reboot, backup), selection (group, labels, "skip who already has"), concurrency, canary, wait after the canary (0 = confirmation), stop threshold, maintenance windows, expiry.

- Canary: the instances labelled `canary=true` go first. Keep a few low-risk instances with that label.
- Only online instances are started; an offline one waits while the rollout lasts.
- Halted (threshold or canary failure): look at the failed targets, then Riprendi (the failures seen are accepted) or Riprova falliti.
- Maintenance windows: group edit → Finestra di manutenzione (manager's local time; a customer without one uses its partner's).

### OS updates and reboots

Instance page → Sistema: Aggiorna liste, Aggiornamenti di sicurezza (unattended-upgrade), Aggiorna tutto (apt upgrade, holds respected), Riavvia, Annulla riavvio. Or a rollout of the same.

A reboot with a newer kernel installed boots it **on trial**: the old kernel stays the GRUB default until the instance reconnects to the manager; otherwise after 15 minutes it reboots into the old kernel and the trial is reported as failed (e-mail). A kernel panic reboots after 10 s (`panic=10`) into the default one.

### Vulnerabilities

How it works ("Come funziona" on the Vulnerabilità page): the instance sends its packages (OS and MADMIN venv) and the available updates when they change; the manager checks them against OSV and the Ubuntu tracker status of each CVE (daily and at every change); each finding gets a status:

- **Correggibile**: the fix is in the Ubuntu archive. The instance's Sistema tab shows which update installs it.
- **Serve release MADMIN**: a Python package of the MADMIN venv with a fixed version: build a release with the newer package (`requirements.lock`).
- **In arrivo** (pending), **Senza correzione** (needed, triage, deferred), **Non verrà corretta** (ignored, eol, ESM only), **Da verificare** (Ubuntu's data older than the installed version).

Only fixable critical findings raise the menu badge and the e-mail.

### Automatic updates, service restarts, reboots

- Every instance installs the **security updates by itself every day** (Ubuntu's unattended-upgrades): only the security pocket of the installed Ubuntu release (fixed versions of the same packages, as Ubuntu does by default, made explicit in `/etc/apt/apt.conf.d/99madmin-unattended-upgrades`), never the normal updates (`-updates`: only "Aggiorna tutto") and never another Ubuntu release, at the time set in Settings → Aggiornamenti automatici (default 03:00 Europe/Rome, plus up to 30 random minutes), or the group's own time (group edit; a customer without one takes its partner's). The manager applies it to each instance (`os.autoupdate.set`) and checks it at every connection.
- After installing, needrestart **restarts the services** that use the updated libraries (a few seconds each: IPsec tunnels and OpenVPN clients reconnect). That is why the time is at night.
- The instance **never reboots by itself** (`/etc/apt/apt.conf.d/99madmin-unattended-upgrades`, shipped with MADMIN).
- **Riavvio consigliato** (red, badge on Istanze, e-mail): the reboot fixes critical or high findings of the running kernel (the fixed kernel is installed, not booted), or the CPU microcode changed. **Riavvio richiesto** (grey) is Ubuntu's flag for any new kernel or libc: it can wait for the next maintenance.
- Services still running old libraries (a restart that failed) are listed on the Sistema tab: Riavvia ora, or at a time.
- **Scheduling**: Rollout → Nuovo rollout → Avvio "A un orario" (once), or Nuova pianificazione (every day / chosen days at a time), e.g. every Sunday 04:00 reboot of the instances with *riavvio consigliato*, every night services restart of the instances that need it.

### What the two OS updates install

Instance → Sistema → Aggiornamenti disponibili lists every upgradable package, coloured:

| Colour | Meaning | Installed by |
|---|---|---|
| red | security update fixing critical/high findings | both |
| orange | security update | both |
| blue | normal update (bug fixes) | only Aggiorna tutto |
| grey | held back: Ubuntu's phased rollout (a % of machines at a time), `apt-mark hold`, or kept back by apt | neither |

"Aggiornamenti di sicurezza" runs `unattended-upgrade` (the security pocket and ESM, as configured on the instance); "Aggiorna tutto" runs `apt-get upgrade --with-new-pkgs`. The confirmation lists exactly what will be installed and the findings it fixes. "Ricontrolla ora" runs `apt-get update` and refreshes the list.

### When MADMIN does not start (rescue)

The instance page shows a Rescue card (unit state, log, update journal) while `madmin-rescue` reports, every 5 minutes. Actions: restart, rollback to the previous release, install a release. From the console: `/opt/madmin/updater/madmin-update status|rollback|recover`.

## 3. Support access

1. TOTP: mandatory for superusers, set up at the first login (lost authenticator: another superuser resets it from Utenti, or as root `sudo -u madmin-manager /opt/madmin-manager/venv/bin/python -m core.auth reset-2fa <user>` from `/opt/madmin-manager/backend`).
2. Supporto → Le mie chiavi SSH: add your public key (with a TOTP code); another superuser approves it (with their TOTP code) after checking the fingerprint with you on another channel (single superuser: `sudo -u madmin-manager /opt/madmin-manager/venv/bin/python -m manager.keys approve <user> <fingerprint>` from `/opt/madmin-manager/backend`). Every key change is mailed to all superusers: give every superuser an e-mail address. A new superuser, or one whose password or 2FA someone else reset, approves keys only after 24 h.
3. Instance → Supporto → Accesso UI / Accesso SSH: duration (max 1 day), reason, your IP, a fresh TOTP code.

At most 4 open sessions per user. The sshd log of the instance names the user and the key fingerprint.

## 4. Keys and certificates

- Release signing keys: two Ed25519 keys (vault + second method). Rotation: ship the new public key in a release signed by the old one (`scripts/release-keys/`), then sign with the new one.
- Manager CA rotation: `python -m manager.pki rotate-ca status|prepare|activate|retire` (see `PROTOCOL.md`, CA rotation).
- Manager address change: instance page → Cambia indirizzo (keep the old address reachable until it is confirmed).

## 5. Notifications

Settings → Notifiche e-mail: SMTP server, sender, recipients (empty = every superuser with an e-mail), test button. Without SMTP only the menu badges remain.
