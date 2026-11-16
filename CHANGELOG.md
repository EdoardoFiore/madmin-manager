# Changelog

All notable changes to MADMIN Manager. Versions follow [Semantic Versioning](https://semver.org/):

- **patch** (1.1.1): fixes only;
- **minor** (1.2.0): new features, schema steps, new API;
- **major**: a break of compatibility with the agents (never while protocol v1 lasts) or of the provisioning API.

Every block of work that is pushed bumps the version (`MANAGER_VERSION` in `backend/config.py`), adds an entry here and is tagged `vX.Y.Z`. The manager is updated by rerunning `setup-manager.sh` from a checkout of the version (schema steps run at startup). The wire protocol has its own versioning (`docs/PROTOCOL.md`), the MADMIN instances theirs (MADMIN `CHANGELOG.md`).

## [1.6.0] - 2026-11-16

### Added
- Certificate of the UI, separate from the agent port's: Settings → Certificato della UI installs an own certificate (certificate, key, optional CA bundle), checked before use (key matches, validity, chain put in order, valid for the name in use), with a fresh 2FA code, and removed again with "Torna a quello interno". `GET/POST/DELETE /api/settings/ui-certificate`. The agent port (8443) keeps the certificate of the manager CA.
- nginx is reloaded by a root path unit (`madmin-manager-nginx-reload.path`) that the service asks by writing a file; the change is confirmed by reading the certificate nginx presents, otherwise the previous one is put back.
- `python -m manager.uicert reset` to go back to the internal certificate from the shell.

### Changed
- **Rerun `setup-manager.sh` to update**: the UI server of nginx now reads `DATA_DIR/ui-tls/` and the reload units are installed by it. `UI_PORT` is written to `.env`.

## [1.5.0] - 2026-11-15

### Changed
- `setup-manager.sh` rerun over an existing manager (the update): `sudo bash scripts/setup-manager.sh` with no options. The administrator password is asked only when the database has no user yet (before, every rerun needed one, then ignored it). Without `--host`/`--ip` the endpoint certificate is reissued with its current names; given ones must include all of them, else the script stops before changing anything (`--replace-names` drops a name on purpose): before, a name left out was dropped and the instances using it stopped connecting.

### Fixed
- README: the update section still said there were no schema migrations.

## [1.4.2] - 2026-11-15

### Fixed
- Instances: on a wide screen the search block of the tree panel took half of its height, leaving an empty space above "Tutte le istanze"; it keeps its own height and the tree takes the rest.

## [1.4.1] - 2026-11-15

### Fixed
- An update to an older release (or to one whose `min_from` is above the installed version) was sent to the instance, whose updater then refused it: the manager now applies the same rule (`allow_downgrade_from`, `min_from`). `POST /api/instances/{id}/update` answers 409, a rollout skips that instance with the reason (not counted as a failure), and "Aggiorna MADMIN" lists only the releases the instance accepts. The release summary of `GET /api/releases` carries `allow_downgrade_from`.

## [1.4.0] - 2026-11-15

Fixes from the security audit of 2026-11-15 (findings F1-F15).

### Security
- An anonymous POST to `/api/releases` (up to 1 GB) was read into memory by the audit middleware before the route refused it: only JSON or form bodies up to 50 KB are read for the log now (F1).
- Login: the block on a target username no longer escalates (it locked a chosen account, its owner's correct password included, from any address); 5 wrong 2FA codes suspend the 2FA for 15 minutes and mail the superusers, instead of a permanent lock and the revocation of every session (F2).
- The TOTP replay guard is one atomic UPDATE: two concurrent requests with the same code both passed (F4).
- Support: a new UI ticket asks a fresh 2FA code and is given only to the operator of the session (F5); the SSH certificate principal is `madmin-support-<instance id>`, named by the manager, never taken from the instance's answer (F6).
- Values reported by instances (resource line, update result, rescue free disk) are escaped on the instance page; heartbeat stats keep numbers only (F3).
- nginx sets `X-Forwarded-For` on the agent server (the client's own header reached uvicorn's access log) (F7).
- A first install needs `--ui-allow` (or `--ui-allow-any` for a test manager); a reinstall with an open UI warns (F8).
- A new password or a 2FA reset for another superuser, and a new API key, take the caller's fresh 2FA code (F9); an API key with `provisioning.enroll` needs allowed networks (F10).
- Token-less registration: at most 20 pending requests per source address; mail subjects without control characters (F11).
- At most 64 interface addresses per report, and none from facts too large to keep (F12).
- A command result resolves the waiting call only when it comes from the instance the command was sent to (F13).
- The installer keeps passwords out of process arguments; `-p/--password` is gone (F14).
- Manager backups start with an HMAC-SHA256 of the encrypted payload, checked by `manager-restore.sh` before decrypting; older archives are restored with a warning (F15).

### Changed (API)
- `POST /api/support/{id}/ticket` takes `{"totp": "..."}`; `POST /api/apikeys` takes `totp`; `DELETE /api/auth/users/{u}/2fa` takes `{"totp": "..."}` when the target is a superuser; `PATCH /api/auth/users/{u}` takes `totp` when it sets another superuser's password.

## [1.3.3] - 2026-11-14

### Fixed
- Menu counts (badges) stayed until a page reload after an action (an SSH key approved, a request handled): they are fetched again after every change made from the UI, and every 30 s (was 60 s).
- Instance detail: the tab shown is redrawn in place as soon as a command changes state (a backup appears when it is done, packages after an upgrade, progress on Panoramica and Comandi), polled every 3 s while a command runs, 15 s otherwise.
- Rollouts: progress and the open detail follow by themselves while a rollout runs or waits, without the spinner.
- Vulnerabilità: after "Scansiona ora" (or while a scan runs) the page shows the results when the scan ends.
- Automatic redraws wait while a modal or a menu is open or a field has the focus.

## [1.3.2] - 2026-11-14

### Fixed
- Forced 2FA setup at login: the page was cut at the top when taller than the window; now a wider card in three numbered steps (scan, save the backup codes, enter the code), with a text that fits superusers too.

## [1.3.1] - 2026-11-14

### Fixed
- `python -m core.auth reset-2fa` failed on the user table's foreign keys (manager models not loaded); `python -m core.settings agent-url` prints a one-line error.

## [1.3.0] - 2026-11-14

### Added
- TOTP mandatory for every superuser: the login asks to set it up, sessions of a superuser without it are refused, a superuser cannot turn it off. Root CLI `python -m core.auth reset-2fa <user>` for a lost authenticator.
- A fresh TOTP code to add an SSH key (owner), to approve one (approver), to create or promote a superuser (caller).
- E-mail to every superuser (and the Settings addresses) at every SSH key change and at every new superuser or superuser password/2FA reset, never throttled.
- A new superuser (UI or LDAP), or one whose password or 2FA another user reset, approves SSH keys only after 24 h (schema step 0007, `user.key_approval_after`).
- Root CLI `python -m core.settings agent-url`: the installer no longer logs in to write the agent URL.

## [1.2.3] - 2026-11-13

### Fixed
- The "Azioni" menu of the Sistema tab was covered by the table headers (sticky headers above dropdowns).

### Changed
- The automatic updates are described as what they are: only the security updates of the installed Ubuntu release (tile, system details, Settings, OPERATIONS.md).

## [1.2.2] - 2026-11-13

### Changed
- Sistema tab reorganised: four status tiles (vulnerabilities to fix, reboot, updates, automatic updates), one suggested action and an "Azioni" menu; vulnerabilities, available updates, system details, installed packages and recent changes in collapsible sections; explanations moved to tooltips.
- Instance page: rarely used actions (change manager address, re-enroll token, suspend, resume, revoke) in a "…" menu.

### Fixed
- Vulnerabilità page: Internal Server Error on the advisories list (a parameter named like the helper it called).

## [1.2.1] - 2026-11-13

### Fixed
- A different running kernel (after a reboot) did not trigger a vulnerability scan: findings and "riavvio consigliato" stayed those of the previous kernel until the daily scan.

## [1.2.0] - 2026-11-13

### Added
- Reboot worth it: findings of the running kernel fixed by a kernel already installed get the status "Corretta, serve riavvio" (not counted as fixable); "riavvio consigliato" when the reboot fixes critical/high findings or the microcode changed (Sistema tab, Vulnerabilità card and column, badge on Istanze, e-mail once per installed kernel). Ubuntu's "riavvio richiesto" stays informative.
- Time of the automatic security updates: Settings (default 03:00 Europe/Rome, random delay) and per group (inherited from the partner), applied to each instance with `os.autoupdate.set` and reconciled at every connection and change.
- Services running outdated libraries (from the instance) with "Riavvia servizi" now or at a time (`os.services.restart`).
- Rollouts: action "Riavvio servizi", filters by state (services to restart, reboot recommended/required), start at a chosen time; recurring schedules (days and time) that create rollouts.
- Sistema tab: the preview of the updates, the freshness of the data and the automatic update time.

### Fixed
- `instances.js` had been emptied by the 1.1.0 change (the instance pages did not load in 1.1.0–1.1.2): restored with the Sistema tab changes.

## [1.1.2] - 2026-11-13

### Fixed
- Updates preview: a CVE listed twice keeps the higher severity of the two records.

## [1.1.1] - 2026-11-13

### Fixed
- Updates preview counted a CVE twice when Ubuntu's record and its USN both list it.

## [1.1.0] - 2026-11-13

First tracked version after 1.0.0 (the work below was developed while the version stayed 1.0.0).

### Added
- Rename hub → manager; protocol v1 frozen: revisions, versioned capabilities, structured errors, long commands, state reconciliation, close codes, `manager.relocate`, CA rotation.
- Signed releases: upload, channels candidate/stable, update of an instance, rescue actions.
- Schema migrations (`backend/core/migrations/`, steps 0001–0005); `manager-backup.sh` / `manager-restore.sh`.
- Support hardening: TOTP at every opening, SSH only to the user's approved keys (`manager.keys`), at most 4 open sessions per user; `setup-manager.sh --ui-allow`.
- Inventory and vulnerabilities: OSV scan, Ubuntu tracker status of each finding (Canonical VEX), Vulnerabilità page, Sistema tab, CSV export; only fixable critical findings alert.
- Preview of the OS updates (what "Aggiornamenti di sicurezza" and "Aggiorna tutto" install, with the findings each package fixes), "Come funziona" panel.
- OS actions from the manager (refresh, upgrade, reboot with kernel on trial, cancel).
- Rollouts (canary, concurrency, stop threshold, maintenance windows), notifications (menu badges, e-mail), LDAP/AD users.
- One form kit for every modal (required/optional marks, hints, inline errors, coloured consequences, typed confirmations).

### Fixed
- Python findings are fixed by a MADMIN release, not by OS updates (status "Serve release MADMIN").
- SMTP port validator shadowed; LDAP user committed before the login answer; users API without `auth_source`.

## [1.0.0]

MADMIN Hub renamed: inventory, backups, support access, licenses, enrollment.
