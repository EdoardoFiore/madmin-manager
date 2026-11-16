/**
 * MADMIN Manager - Settings.
 *
 * A menu of sections on the left, one section at a time on the right. Each
 * section is its own form: "Salva" sends only the fields that changed in it,
 * a dot in the menu marks the sections with unsaved changes.
 */
import { apiGet, apiPatch, apiPost, apiDelete } from '../api.js';
import { escapeHtml, showToast } from '../utils.js';
import { checkPermission } from '../app.js';
import { formModal, formData, field, notice, confirmAction, fmtDate, otpField, validateForm, formSection } from './manager-common.js';

const TIMEZONES = (() => { try { return Intl.supportedValuesOf('timeZone'); } catch { return []; } })();

// Field: k (setting), label, type (text, number, password, select, checkbox,
// color, time, textarea, rules), hint (HTML), col, unit (suffix), min, max,
// maxlength, options, placeholder, rows, mono, list (datalist id).
const SECTIONS = [
    { group: 'Manager', id: 'general', icon: 'ti-adjustments', title: 'Generale',
      desc: 'Nome e aspetto del manager, regole delle password.', blocks: [
        { title: 'Aspetto', fields: [
            { k: 'company_name', label: 'Nome', col: 'col-md-6', maxlength: 100, hint: 'Nel menu, nel titolo della pagina e nelle e-mail.' },
            { k: 'primary_color', label: 'Colore principale', type: 'color', col: 'col-6 col-md-3' },
            { k: 'default_language', label: 'Lingua predefinita', type: 'select', col: 'col-6 col-md-3', options: [['it', 'Italiano'], ['en', 'English']] },
        ] },
        { title: 'Password degli utenti locali', fields: [
            { k: 'password_max_age_days', label: 'Scadenza', type: 'number', min: 0, max: 3650, unit: 'giorni', col: 'col-md-4', hint: '0 = non scadono mai.' },
        ] },
    ] },
    { group: 'Manager', id: 'certs', icon: 'ti-certificate', title: 'Certificati',
      desc: 'Il certificato dell\'interfaccia web e quello della porta a cui si collegano le istanze.', custom: true },
    { group: 'Manager', id: 'mail', icon: 'ti-mail', title: 'Notifiche e-mail',
      desc: 'Avvisi per ciò che richiede una persona: richieste di registrazione, chiavi SSH da approvare, aggiornamenti falliti, vulnerabilità critiche, certificati in scadenza.',
      test: { id: 'smtp-test', label: 'Invia e-mail di prova', icon: 'ti-send' }, blocks: [
        { title: 'Server di posta', note: 'Senza server non parte nessuna e-mail: restano i contatori nel menu.', fields: [
            { k: 'smtp_host', label: 'Server SMTP', col: 'col-md-6', placeholder: 'smtp.example.com' },
            { k: 'smtp_port', label: 'Porta', type: 'number', min: 1, max: 65535, col: 'col-6 col-md-3' },
            { k: 'smtp_encryption', label: 'Cifratura', type: 'select', col: 'col-6 col-md-3', options: [['tls', 'STARTTLS'], ['ssl', 'SSL/TLS'], ['none', 'Nessuna']] },
            { k: 'smtp_username', label: 'Utente', col: 'col-md-6', hint: 'Vuoto = senza autenticazione.' },
            { k: 'smtp_password', label: 'Password', type: 'password', col: 'col-md-6', hint: 'Vuoto = resta quella salvata.' },
        ] },
        { title: 'Messaggi', fields: [
            { k: 'smtp_from', label: 'Mittente', col: 'col-md-6', placeholder: 'manager@example.com' },
            { k: 'notify_to', label: 'Destinatari', col: 'col-md-6', placeholder: 'noc@example.com, ops@example.com', hint: 'Separati da virgola. Vuoto = i superuser che hanno un\'e-mail.' },
        ] },
    ] },
    { group: 'Manager', id: 'ldap', icon: 'ti-address-book', title: 'LDAP / Active Directory',
      desc: 'Login con gli utenti della directory. Gli utenti locali restano validi e un nome utente locale non viene mai cercato nella directory.',
      test: { id: 'ldap-test', label: 'Prova un login', icon: 'ti-plug-connected' }, blocks: [
        { fields: [
            { k: 'ldap_enabled', label: 'Login con gli utenti della directory', type: 'checkbox', hint: 'Entra solo chi corrisponde a una regola di accesso qui sotto. La 2FA del manager è obbligatoria anche per loro.' },
        ] },
        { title: 'Connessione', fields: [
            { k: 'ldap_url', label: 'Server', col: 'col-md-6', mono: true, placeholder: 'ldaps://dc.example.com:636', hint: '<code>ldaps://host:636</code> oppure <code>ldap://host</code> (StartTLS). Con la verifica del certificato attiva serve un nome DNS, non un IP: deve corrispondere al certificato.' },
            { k: 'ldap_base_dn', label: 'Base di ricerca', col: 'col-md-6', mono: true, placeholder: 'dc=example,dc=com' },
            { k: 'ldap_bind_dn', label: 'Account di servizio', col: 'col-md-6', mono: true, placeholder: 'cn=manager,ou=service,dc=example,dc=com', hint: 'Usato solo per cercare utenti e gruppi.' },
            { k: 'ldap_bind_password', label: 'Password dell\'account di servizio', type: 'password', col: 'col-md-6', hint: 'Vuoto = resta quella salvata.' },
            { k: 'ldap_user_filter', label: 'Filtro utente', col: 'col-12', mono: true, hint: '<code>{username}</code> = il nome inserito al login.' },
            { k: 'ldap_starttls', label: 'Cifra la connessione con StartTLS (solo <code>ldap://</code>)', type: 'checkbox', hint: 'Se il controller non ha un certificato, StartTLS non riesce ("startTLS failed"). <b>Disattivata, la password dell\'account di servizio e quelle degli utenti viaggiano in chiaro</b> a ogni login: solo su una rete chiusa e fidata. Meglio <code>ldaps://</code> con un certificato sul controller.' },
            { k: 'ldap_verify_cert', label: 'Verifica il certificato del server', type: 'checkbox', hint: 'Vale se la connessione è cifrata. Disattivata, la connessione resta cifrata ma il server non viene riconosciuto: chi si mette in mezzo può leggere le password. Solo per una rete di cui ti fidi (certificato autofirmato, indirizzo IP).' },
            { k: 'ldap_ca_pem', label: 'CA del server', type: 'textarea', rows: 4, col: 'col-12', placeholder: '-----BEGIN CERTIFICATE-----', hint: 'PEM. Vuoto = le CA di sistema (certificato pubblico). Non serve con la verifica disattivata.' },
        ] },
        { title: 'Chi può entrare', note: 'Una regola per ogni utente o gruppo della directory ammesso, con il tipo di accesso. Chi non corrisponde a nessuna regola non entra.', fields: [
            { k: 'ldap_mappings', type: 'rules' },
        ] },
    ] },
    { group: 'Istanze', id: 'connection', icon: 'ti-plug', title: 'Connessione',
      desc: 'Come le istanze raggiungono il manager e come gli operatori raggiungono le sessioni di supporto.', blocks: [
        { title: 'Indirizzi', fields: [
            { k: 'agent_url', label: 'URL per le istanze', col: 'col-md-6', mono: true, placeholder: 'https://manager.example.com:8443', hint: 'Scritto in ogni token di enrollment. Le istanze già registrate non lo cambiano da qui (istanza → Cambia indirizzo).' },
            { k: 'support_host', label: 'Host delle porte di supporto', col: 'col-md-6', mono: true, hint: 'Quello che usano gli operatori. Vuoto = l\'host dell\'URL per le istanze.' },
            { k: 'support_port_min', label: 'Prima porta di supporto', type: 'number', min: 1024, max: 65535, col: 'col-6 col-md-3' },
            { k: 'support_port_max', label: 'Ultima porta di supporto', type: 'number', min: 1024, max: 65535, col: 'col-6 col-md-3', hint: 'Una porta per sessione aperta, al massimo 200.' },
        ] },
        { title: 'Agent delle istanze', note: 'Applicato a ogni istanza alla connessione successiva.', fields: [
            { k: 'agent_heartbeat_interval', label: 'Heartbeat ogni', type: 'number', min: 30, max: 600, unit: 'secondi', col: 'col-md-4', hint: '30-600.' },
            { k: 'agent_facts_interval', label: 'Controllo dei dati ogni', type: 'number', min: 60, max: 3600, unit: 'secondi', col: 'col-md-4', hint: '60-3600. Versioni, risorse, pacchetti.' },
            { k: 'agent_backoff_max', label: 'Attesa massima tra riconnessioni', type: 'number', min: 30, max: 900, unit: 'secondi', col: 'col-md-4', hint: '30-900.' },
        ] },
    ] },
    { group: 'Istanze', id: 'registration', icon: 'ti-user-plus', title: 'Registrazione senza token',
      desc: 'Un\'istanza installata con il solo indirizzo del manager manda una richiesta, da approvare in Enrollment → In attesa.', blocks: [
        { fields: [
            { k: 'registration_enabled', label: 'Accetta richieste di registrazione', type: 'checkbox', hint: 'Disattivata: si registra solo chi ha un token.' },
            { k: 'registration_allowed_cidrs', label: 'Solo da queste reti', col: 'col-12', mono: true, placeholder: '10.0.0.0/8, 192.0.2.0/24', hint: 'Indirizzi o reti separati da virgola. Vuoto = da qualsiasi indirizzo.' },
            { k: 'registration_ttl_days', label: 'Scadenza delle richieste', type: 'number', min: 1, max: 90, unit: 'giorni', col: 'col-md-4', hint: 'Non approvate entro questo tempo vengono eliminate.' },
            { k: 'registration_max_pending', label: 'Richieste in attesa', type: 'number', min: 1, max: 10000, unit: 'al massimo', col: 'col-md-4' },
        ] },
    ] },
    { group: 'Istanze', id: 'updates', icon: 'ti-refresh', title: 'Aggiornamenti',
      desc: 'Aggiornamenti di sicurezza automatici del sistema operativo e firma delle release di MADMIN.', blocks: [
        { title: 'Aggiornamenti automatici di sicurezza', note: 'Ogni giorno, solo gli aggiornamenti di sicurezza della versione di Ubuntu installata: mai quelli normali, mai un\'altra versione di Ubuntu. Poi riavvio dei servizi che li usano, mai della macchina. Un gruppo può avere un\'ora diversa.', fields: [
            { k: 'autoupdate_time', label: 'Ora', type: 'time', col: 'col-6 col-md-3' },
            { k: 'autoupdate_tz', label: 'Fuso orario', col: 'col-6 col-md-5', list: 'settings-timezones', placeholder: 'Europe/Rome' },
            { k: 'autoupdate_randomize', label: 'Ritardo casuale', type: 'number', min: 0, max: 180, unit: 'minuti', col: 'col-md-4', hint: '0-180. Le istanze non si aggiornano tutte nello stesso istante.' },
        ] },
        { title: 'Firma delle release', fields: [
            { k: 'release_keys', label: 'Chiavi pubbliche di firma', type: 'textarea', rows: 6, col: 'col-12', placeholder: '-----BEGIN PUBLIC KEY-----', hint: 'PEM, una o più. Una release caricata deve essere firmata da una di queste. Vuoto = non verificata dal manager (le istanze la verificano sempre).' },
        ] },
    ] },
    { group: 'Istanze', id: 'backups', icon: 'ti-database', title: 'Backup e licenze',
      desc: 'Backup pianificati delle istanze sul manager e durata dei token di licenza dei moduli.', blocks: [
        { title: 'Backup', fields: [
            { k: 'backup_interval_hours', label: 'Backup pianificato ogni', type: 'number', min: 0, max: 3650, unit: 'ore', col: 'col-md-4', hint: '0 = nessun backup pianificato.' },
            { k: 'backup_retention', label: 'Backup conservati', type: 'number', min: 1, max: 365, unit: 'per istanza', col: 'col-md-4', hint: 'I più vecchi vengono eliminati.' },
        ] },
        { title: 'Licenze', fields: [
            { k: 'license_validity_days', label: 'Durata di un token di licenza', type: 'number', min: 3, max: 365, unit: 'giorni', col: 'col-md-4', hint: '3-365. Rinnovato da solo finché la licenza è attiva: è il tempo per cui un\'istanza scollegata resta licenziata.' },
        ] },
    ] },
];

const fieldsOf = (sec) => (sec.blocks || []).flatMap((b) => b.fields);
const DOTS = '••••••••';
const hexColor = (v) => /^#[0-9a-f]{3}$/i.test(v || '') ? '#' + [...v.slice(1)].map((c) => c + c).join('') : (v || '#206bc4');

// ---------------------------------------------------------------- fields

function control(f, ro) {
    if (f.type === 'rules') return '<input type="hidden" name="ldap_mappings"><div class="col-12" id="ldap-rules"></div>';
    const dis = ro ? 'disabled' : '';
    const id = `set-${f.k}`;
    const hint = f.hint ? `<div class="form-hint">${f.hint}</div>` : '';
    const fb = '<div class="invalid-feedback"></div>';
    if (f.type === 'checkbox') {
        return `<div class="${f.col || 'col-12'}"><label class="form-check form-switch mb-0">
            <input class="form-check-input" type="checkbox" name="${f.k}" id="${id}" ${dis}>
            <span class="form-check-label fw-medium">${f.label}</span></label>${hint}</div>`;
    }
    const cls = `form-control${f.mono ? ' font-monospace' : ''}`;
    const ph = f.placeholder ? `placeholder="${escapeHtml(f.placeholder)}"` : '';
    let input;
    if (f.type === 'textarea') {
        input = `<textarea class="form-control font-monospace small" name="${f.k}" id="${id}" rows="${f.rows || 4}" spellcheck="false" ${ph} ${dis}></textarea>${fb}`;
    } else if (f.type === 'select') {
        input = `<select class="form-select" name="${f.k}" id="${id}" ${dis}>${f.options.map(([v, l]) =>
            `<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`).join('')}</select>${fb}`;
    } else if (f.type === 'color') {
        input = `<input type="color" class="form-control form-control-color w-100" name="${f.k}" id="${id}" ${dis}>${fb}`;
    } else {
        const a = [
            f.type === 'number' || f.type === 'time' ? 'required' : '',
            f.min != null ? `min="${f.min}"` : '', f.max != null ? `max="${f.max}"` : '',
            f.maxlength ? `maxlength="${f.maxlength}"` : '', f.list ? `list="${f.list}"` : '',
            f.type === 'password' ? 'autocomplete="new-password"' : 'autocomplete="off"', ph, dis,
        ].filter(Boolean).join(' ');
        input = `<input type="${f.type || 'text'}" class="${cls}" name="${f.k}" id="${id}" ${a}>`;
        input = f.unit
            ? `<div class="input-group has-validation">${input}<span class="input-group-text">${f.unit}</span>${fb}</div>`
            : input + fb;
    }
    return `<div class="${f.col || 'col-12'}"><label class="form-label" for="${id}">${f.label}</label>${input}${hint}</div>`;
}

function read(form, f) {
    const el = form.elements[f.k];
    if (f.type === 'checkbox') return el.checked;
    const v = el.value.trim();
    return f.type === 'number' ? (v === '' ? null : Number(v)) : v;
}

// ---------------------------------------------------------------- LDAP access rules

// ldap_mappings: [{user | group, role, access, group_id}]. A rule for a user
// always wins over the rules for groups; among groups, the first that matches.
const ROLES = [['superuser', 'Superuser'], ['partner', 'Partner'], ['customer', 'Cliente']];
const ACCESS = [['rw', 'Lettura e scrittura'], ['ro', 'Sola lettura']];

function parseRules(raw) {
    let items = [];
    try { items = JSON.parse(raw || '[]'); } catch { /* shown empty: saving rewrites it */ }
    return (Array.isArray(items) ? items : []).map((m) => ({
        type: m.user ? 'user' : 'group', name: m.user || m.group || '',
        role: m.role || 'customer', access: m.access || 'ro', group_id: m.group_id || '',
    }));
}

const serializeRules = (rules) => JSON.stringify(rules.map((r) => ({
    [r.type]: r.name.trim(), role: r.role, access: r.access,
    ...(r.role === 'superuser' ? {} : { group_id: r.group_id }),
})));

function rulesEditor(form, groups, ro, getBase) {
    const box = form.querySelector('#ldap-rules');
    const hidden = form.elements.ldap_mappings;
    let rules = [];
    const opts = (list, sel) => list.map(([v, l]) => `<option value="${escapeHtml(v)}" ${v === sel ? 'selected' : ''}>${escapeHtml(l)}</option>`).join('');
    const dis = ro ? 'disabled' : '';

    function draw() {
        hidden.value = serializeRules(rules);
        box.innerHTML = `
            ${rules.length ? `<div class="table-responsive border rounded mb-2"><table class="table table-vcenter mb-0">
                <thead><tr><th>Utente o gruppo della directory</th><th>Ruolo</th><th>Accesso</th><th>Vede</th><th class="w-1"></th></tr></thead>
                <tbody>${rules.map((r, i) => {
                    const kind = r.role === 'partner' ? 'partner' : 'customer';
                    const own = groups.filter((g) => g.kind === kind);
                    return `<tr data-rule="${i}">
                        <td style="min-width: 22rem"><div class="input-group has-validation">
                            <select class="form-select flex-grow-0 w-auto" data-f="type" ${dis}>${opts([['user', 'Utente'], ['group', 'Gruppo']], r.type)}</select>
                            <input class="form-control font-monospace" data-f="name" required maxlength="500" value="${escapeHtml(r.name)}" ${dis}
                                placeholder="${r.type === 'user' ? 'mario.rossi' : 'cn=noc,ou=groups,dc=example,dc=com'}">
                            <div class="invalid-feedback"></div></div></td>
                        <td><select class="form-select" data-f="role" ${dis}>${opts(ROLES, r.role)}</select></td>
                        <td><select class="form-select" data-f="access" ${dis}>${opts(ACCESS, r.access)}</select></td>
                        <td style="min-width: 12rem">${r.role === 'superuser'
                            ? '<span class="text-muted">Tutte le istanze</span>'
                            : `<select class="form-select" data-f="group_id" required ${dis}>
                                <option value="">${own.length ? 'Scegli il gruppo…' : `Nessun gruppo ${kind === 'partner' ? 'partner' : 'cliente'}`}</option>
                                ${opts(own.map((g) => [g.id, g.path || g.name]), r.group_id)}</select><div class="invalid-feedback"></div>`}</td>
                        <td>${ro ? '' : `<div class="btn-list flex-nowrap">
                            <button type="button" class="btn btn-icon btn-ghost-secondary btn-sm" data-act="up" title="Sposta su" ${i ? '' : 'disabled'}><i class="ti ti-arrow-up"></i></button>
                            <button type="button" class="btn btn-icon btn-ghost-danger btn-sm" data-act="del" title="Togli la regola"><i class="ti ti-trash"></i></button>
                        </div>`}</td></tr>`;
                }).join('')}</tbody></table></div>`
            : '<div class="text-muted border rounded p-3 mb-2">Nessuna regola: nessun utente della directory può entrare.</div>'}
            ${ro ? '' : `<div class="btn-list">
                <button type="button" class="btn btn-outline-primary btn-sm" data-act="search"><i class="ti ti-search me-1"></i>Cerca nella directory</button>
                <button type="button" class="btn btn-outline-secondary btn-sm" data-act="add"><i class="ti ti-plus me-1"></i>Aggiungi a mano</button>
            </div>`}
            <div class="form-hint mt-2">Una regola per <b>utente</b> vince sempre su quelle per <b>gruppo</b>; tra i gruppi vale la prima che corrisponde.
                Si applica al login successivo ed entro 15 minuti a chi è già entrato: chi non corrisponde più viene disattivato.</div>`;
    }

    function changed() {
        hidden.value = serializeRules(rules);
        form.dispatchEvent(new Event('input'));
    }

    box.addEventListener('input', (e) => {
        const row = e.target.closest('[data-rule]');
        const key = e.target.dataset.f;
        if (!row || !key) return;
        const r = rules[Number(row.dataset.rule)];
        r[key] = e.target.value;
        if (key === 'role') r.group_id = '';
        hidden.value = serializeRules(rules);
        // Type and role change what the row shows
        if (key === 'type' || key === 'role') draw();
    });
    box.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-act]');
        if (!btn) return;
        const i = Number(btn.closest('[data-rule]')?.dataset.rule);
        const act = btn.dataset.act;
        if (act === 'add') rules.push({ type: 'user', name: '', role: 'customer', access: 'ro', group_id: '' });
        else if (act === 'del') rules.splice(i, 1);
        else if (act === 'up') rules.splice(i - 1, 2, rules[i], rules[i - 1]);
        else if (act === 'search') return directorySearch(groups, getBase(), (items, grant) => {
            let added = 0;
            for (const it of items) {
                if (rules.some((r) => r.type === it.kind && r.name.toLowerCase() === it.value.toLowerCase())) continue;
                rules.push({ type: it.kind, name: it.value, ...grant });
                added++;
            }
            draw(); changed();
            return { added, skipped: items.length - added };
        });
        draw(); changed();
    });

    return { set(raw) { rules = parseRules(raw); draw(); } };
}

/**
 * Users and groups under a folder of the directory (the saved connection):
 * the folder, a search in it or the whole list, then tick who to add. The
 * same role, access and manager group go to everyone ticked.
 */
function directorySearch(groups, base, onAdd) {
    const el = formModal('Cerca nella directory', `
        ${notice('info', '', [['ti-info-circle', 'Cerca con la connessione <b>salvata</b>, nel percorso indicato e nelle sue sottocartelle.']])}
        ${field('base', 'Percorso', { required: true, mono: true, value: base, maxlength: 500, example: 'ou=Utenti,dc=example,dc=com',
            hint: 'La cartella (OU) della directory dove cercare: deve stare dentro la base di ricerca.' })}
        ${field('query', 'Nome, utente o e-mail', { maxlength: 100, attrs: 'autocomplete="off"', example: 'rossi' })}
        <div class="btn-list mb-3"><button type="submit" class="btn btn-primary btn-sm" data-search><i class="ti ti-search me-1"></i>Cerca</button>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-all><i class="ti ti-list me-1"></i>Elenca tutti</button></div>
        <div id="dir-found"></div>`,
    async (form) => { await run(form, false); return false; },
    { submitText: 'Cerca', icon: 'ti-search', size: 'lg' });
    // The footer button is the same as the one in the form: keep a single one
    el.querySelector('.modal-footer [type=submit]').classList.add('d-none');
    const form = el.querySelector('form');
    const box = el.querySelector('#dir-found');
    const errorBox = form.querySelector('[data-form-error]');

    const showError = (msg) => { errorBox.textContent = msg; errorBox.classList.remove('d-none'); };
    async function run(f, everything) {
        errorBox.classList.add('d-none');
        const d = formData(f);
        if (!d.base) throw new Error('Indicare il percorso');
        if (!everything && (d.query || '').length < 2) throw new Error('Scrivere almeno 2 caratteri, oppure usare "Elenca tutti"');
        box.innerHTML = '<div class="text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Ricerca in corso…</div>';
        let r;
        try { r = await apiPost('/settings/ldap/search', { base: d.base, query: d.query || '', everything }); }
        catch (err) { box.innerHTML = ''; throw err; }
        show(r);
    }
    form.querySelector('[data-all]').addEventListener('click', async () => {
        try { await run(form, true); } catch (err) { showError(err.message || 'Errore'); }
    });

    function show(r) {
        const row = (it, i) => `<label class="list-group-item d-flex align-items-center gap-2">
            <input type="checkbox" class="form-check-input m-0" data-pick="${it.kind}:${i}">
            <i class="ti ${it.kind === 'user' ? 'ti-user' : 'ti-users-group'} text-muted"></i>
            <div class="flex-fill text-truncate">
                <div class="text-truncate">${escapeHtml(it.label)}${it.disabled ? ' <span class="badge bg-warning-lt ms-1">Disattivato nella directory</span>' : ''}</div>
                <div class="small text-muted font-monospace text-truncate">${escapeHtml(it.kind === 'user' ? it.value : it.dn)}${it.mail ? ` · ${escapeHtml(it.mail)}` : ''}</div>
            </div></label>`;
        const list = (title, items, kind) => items.length ? `
            <div class="d-flex align-items-center mt-3 mb-1"><h4 class="mb-0">${title} <span class="text-muted fw-normal">(${items.length})</span></h4>
                <label class="form-check ms-auto mb-0 small"><input type="checkbox" class="form-check-input" data-all-of="${kind}"><span class="form-check-label">Seleziona tutti</span></label></div>
            <div class="list-group list-group-flush border rounded" style="max-height: 14rem; overflow-y: auto">${items.map((it, i) => row(it, i)).join('')}</div>` : '';
        const found = { user: r.users, group: r.groups };
        box.innerHTML = (r.users.length || r.groups.length) ? `
            ${r.truncated ? `<div class="alert alert-warning py-2 mt-3 mb-0 small">Mostrati i primi ${r.limit}: restringere il percorso o la ricerca.</div>` : ''}
            ${list('Utenti', r.users, 'user')}${list('Gruppi', r.groups, 'group')}
            ${formSection('Accesso da dare a chi selezioni')}
            <div class="row g-2">
                ${field('grant_role', 'Ruolo', { type: 'select', col: 'col-md-4', value: 'customer', options: ROLES })}
                ${field('grant_access', 'Accesso', { type: 'select', col: 'col-md-4', value: 'ro', options: ACCESS })}
                ${field('grant_group', 'Vede (gruppo del manager)', { type: 'select', col: 'col-md-4', id: 'dir-grant-group' })}
            </div>
            <button type="button" class="btn btn-primary" data-add disabled><i class="ti ti-plus me-1"></i>Aggiungi selezionati</button>
            <span class="small text-muted ms-2" data-add-note></span>`
            : '<div class="text-muted mt-3">Nessun utente o gruppo trovato in questo percorso.</div>';
        if (!box.querySelector('[data-add]')) return;

        const roleSel = box.querySelector('[name=grant_role]');
        const groupSel = box.querySelector('#dir-grant-group');
        const addBtn = box.querySelector('[data-add]');
        const picked = () => [...box.querySelectorAll('[data-pick]:checked:not(:disabled)')].map((c) => {
            const [kind, i] = c.dataset.pick.split(':');
            return { el: c, item: found[kind][Number(i)] };
        });
        const syncRole = () => {
            const wrap = groupSel.closest('.mb-3, [class*="col"]');
            const own = groups.filter((g) => g.kind === (roleSel.value === 'partner' ? 'partner' : 'customer'));
            groupSel.innerHTML = `<option value="">${own.length ? 'Scegli il gruppo…' : 'Nessun gruppo disponibile'}</option>`
                + own.map((g) => `<option value="${escapeHtml(g.id)}">${escapeHtml(g.path || g.name)}</option>`).join('');
            wrap.hidden = groupSel.disabled = roleSel.value === 'superuser';
        };
        const syncAdd = () => {
            const n = picked().length;
            addBtn.disabled = n === 0;
            addBtn.innerHTML = `<i class="ti ti-plus me-1"></i>Aggiungi selezionati${n ? ` (${n})` : ''}`;
        };
        roleSel.addEventListener('change', syncRole);
        box.addEventListener('change', (e) => {
            const all = e.target.dataset?.allOf;
            if (all) box.querySelectorAll(`[data-pick^="${all}:"]:not(:disabled)`).forEach((c) => { c.checked = e.target.checked; });
            syncAdd();
        });
        syncRole();
        syncAdd();
        addBtn.addEventListener('click', () => {
            errorBox.classList.add('d-none');
            const grant = { role: roleSel.value, access: box.querySelector('[name=grant_access]').value,
                            group_id: roleSel.value === 'superuser' ? '' : groupSel.value };
            if (grant.role !== 'superuser' && !grant.group_id) { groupSel.classList.add('is-invalid'); return showError('Scegliere il gruppo del manager che vedranno'); }
            groupSel.classList.remove('is-invalid');
            const chosen = picked();
            const { added, skipped } = onAdd(chosen.map((c) => c.item), grant);
            chosen.forEach(({ el: c }) => { c.checked = false; c.disabled = true; });
            syncAdd();
            box.querySelector('[data-add-note]').textContent =
                `${added} aggiunt${added === 1 ? 'a' : 'e'}${skipped ? `, ${skipped} già present${skipped === 1 ? 'e' : 'i'}` : ''}: salvare la sezione per applicare.`;
        });
    }
}

function ldapTest() {
    const el = formModal('Prova login LDAP', `
        ${notice('info', '', [['ti-info-circle', 'Usa le impostazioni <b>salvate</b>; non crea l\'utente, mostra cosa otterrebbe al login.']])}
        ${field('username', 'Utente', { required: true, maxlength: 100, attrs: 'autocomplete="off"', example: 'mario.rossi' })}
        ${field('password', 'Password', { type: 'password', required: true, attrs: 'autocomplete="new-password"' })}
        <div id="ldap-result"></div>`,
    async (form) => {
        const box = el.querySelector('#ldap-result');
        const r = await apiPost('/settings/ldap/test', formData(form));
        const m = r.mapping;
        box.innerHTML = notice(m ? 'success' : 'warning', m ? 'Login consentito' : 'Login rifiutato: nessuna regola per questo utente o per i suoi gruppi', [
            ['ti-id', `<span class="font-monospace small">${escapeHtml(r.dn)}</span>`],
            m ? ['ti-list-check', `Regola per ${m.user ? 'l\'utente' : 'il gruppo'} <span class="font-monospace small">${escapeHtml(m.user || m.group)}</span>`] : null,
            m ? ['ti-user-shield', `Ruolo <b>${escapeHtml(m.role)}</b>, accesso <b>${escapeHtml(m.access)}</b>${m.group_id ? `, gruppo <span class="font-monospace">${escapeHtml(m.group_id)}</span>` : ''}`] : null,
            ['ti-users-group', `Gruppi: ${r.groups.map(g => `<span class="font-monospace small">${escapeHtml(g)}</span>`).join(', ') || 'nessuno'}`]]);
        return false;
    }, { submitText: 'Prova', icon: 'ti-plug-connected' });
}

// ---------------------------------------------------------------- certificates

// Two certificates: the UI port's (own or internal) and the instances' port's,
// always issued by the manager CA.
function certPanel(sec, c, ro) {
    const head = `<h2 class="mb-1">${sec.title}</h2><p class="text-muted mb-4">${sec.desc}</p>`;
    if (!c) return `<div class="card-body">${head}${notice('warning', '', ['Stato dei certificati non disponibile.'])}</div>`;
    const item = (title, html) => `<div class="datagrid-item"><div class="datagrid-title">${title}</div><div class="datagrid-content">${html}</div></div>`;
    const left = (days) => `<span class="badge bg-${days < 15 ? 'danger' : days < 30 ? 'warning' : 'success'}-lt ms-1">${days < 0 ? 'scaduto' : `${days} giorni`}</span>`;
    return `<div class="card-body">${head}
        <h3 class="card-title mb-1">Interfaccia web
            ${c.custom ? '<span class="badge bg-success-lt ms-2">Certificato proprio</span>' : '<span class="badge bg-secondary-lt ms-2">Certificato interno</span>'}</h3>
        <p class="text-muted small mb-3">${c.custom
            ? 'Non si rinnova da solo: caricare il nuovo prima della scadenza (arriva un\'e-mail a 30, 14, 7, 3 e 1 giorno).'
            : 'Emesso dalla CA del manager, che i browser non conoscono: per questo mostrano un avviso. Caricare un certificato proprio per toglierlo.'}</p>
        ${c.not_after ? `<div class="datagrid mb-3">
            ${item('Valido per', `<span class="font-monospace small text-break">${(c.names || []).map(escapeHtml).join(', ') || '-'}</span>`)}
            ${item('Emesso da', `<span class="text-break">${escapeHtml(c.issuer || '-')}</span>`)}
            ${item('Scadenza', `${fmtDate(c.not_after)}${left(c.days_left)}`)}
        </div>` : ''}
        ${c.installed ? '' : notice('warning', '', ['Non gestito da questa installazione: rieseguire <code>setup-manager.sh</code> di questa versione.'])}
        ${ro || !c.installed ? '' : `<div class="btn-list">
            <button type="button" class="btn btn-primary" id="ui-cert-upload"><i class="ti ti-upload me-1"></i>Carica certificato</button>
            ${c.custom ? '<button type="button" class="btn btn-outline-secondary" id="ui-cert-reset">Torna a quello interno</button>' : ''}
        </div>`}
        ${c.endpoint ? `<h3 class="card-title mt-5 mb-1">Porta delle istanze</h3>
        <p class="text-muted small mb-3">Sempre il certificato emesso dalla CA del manager: le istanze si fidano solo di quella. Qui non si carica nulla.</p>
        <div class="datagrid">
            ${item('Certificato', `${fmtDate(c.endpoint.not_after)} <span class="text-muted">· rinnovo automatico</span>`)}
            ${item('CA del manager', `${fmtDate(c.ca.not_after)}${c.ca.days_left < 365
                ? `<span class="badge bg-${c.ca.days_left < 90 ? 'danger' : 'warning'}-lt ms-1">${c.ca.days_left} giorni: da ruotare</span>
                   <div class="small text-muted">Non si rinnova da sola: <code>python -m manager.pki rotate-ca</code></div>` : ''}`)}
        </div>` : ''}
    </div>`;
}

function uiCertUpload(refresh) {
    const host = location.hostname;
    formModal('Certificato dell\'interfaccia web', `
        ${notice('info', '', [
            ['ti-world', 'Vale solo per l\'interfaccia web. La porta delle istanze resta sul certificato della CA del manager.'],
            ['ti-refresh', 'nginx viene ricaricato: se non presenta il nuovo certificato, torna il precedente.'],
        ])}
        ${field('cert', 'Certificato', { type: 'file', required: true, attrs: 'accept=".crt,.pem,.cer"', hint: 'PEM (.crt, .pem). Può contenere anche la catena.' })}
        ${field('key', 'Chiave privata', { type: 'file', required: true, attrs: 'accept=".key,.pem"', hint: 'PEM, RSA o ECDSA, senza password.' })}
        ${field('chain', 'CA bundle', { type: 'file', attrs: 'accept=".ca-bundle,.crt,.pem,.cer"', hint: 'I certificati intermedi dell\'emittente, se non sono già nel file del certificato.' })}
        ${field('force', `Installa anche se non vale per <span class="font-monospace">${escapeHtml(host)}</span>`, { type: 'checkbox', hint: 'Il nome con cui stai usando la UI ora. Con un certificato per un altro nome il browser mostrerà un avviso su questo.' })}
        ${otpField()}`,
    async (form) => {
        const text = async (name) => (await form.elements[name].files[0]?.text()) || '';
        await apiPost('/settings/ui-certificate', {
            cert_pem: await text('cert'), key_pem: await text('key'), chain_pem: await text('chain'),
            host, force: form.elements.force.checked, totp: form.elements.totp.value.trim(),
        });
        showToast('Certificato installato', 'success', 6000);
        refresh();
    }, { submitText: 'Installa', icon: 'ti-certificate' });
}

async function uiCertReset(refresh) {
    const ok = await confirmAction({
        title: 'Tornare al certificato interno?', tone: 'warning', confirmText: 'Ripristina', icon: 'ti-certificate',
        items: ['Il certificato caricato e la sua chiave vengono eliminati dal manager.',
                'L\'interfaccia web torna al certificato emesso dalla CA del manager: i browser mostreranno di nuovo l\'avviso.'],
    });
    if (!ok) return;
    try {
        await apiDelete('/settings/ui-certificate');
        showToast('Certificato interno ripristinato', 'success');
        refresh();
    } catch (err) { showToast(err.message, 'error', 8000); }
}

// ---------------------------------------------------------------- page

export async function render(container) {
    const ro = !checkPermission('manager.manage');
    let state = await apiGet('/settings/system');
    const groups = await apiGet('/groups').catch(() => []);
    let stored = null;
    try { stored = sessionStorage.getItem('manager-settings-section'); } catch { /* private window */ }
    let active = SECTIONS.some((x) => x.id === stored) ? stored : SECTIONS[0].id;

    const navGroups = [...new Set(SECTIONS.map((x) => x.group))];
    container.innerHTML = `
        <datalist id="settings-timezones">${TIMEZONES.map((z) => `<option value="${z}">`).join('')}</datalist>
        <div class="card"><div class="row g-0">
            <div class="col-12 col-md-4 col-lg-3 border-end"><div class="card-body">
                ${navGroups.map((g, i) => `<h4 class="subheader ${i ? 'mt-4' : ''}">${g}</h4>
                    <div class="list-group list-group-transparent">${SECTIONS.filter((x) => x.group === g).map((x) => `
                        <button type="button" class="list-group-item list-group-item-action d-flex align-items-center text-start" data-nav="${x.id}">
                            <i class="ti ${x.icon} me-2"></i>${x.title}
                            <span class="badge bg-orange ms-auto d-none" data-dirty title="Modifiche non salvate"></span>
                        </button>`).join('')}</div>`).join('')}
            </div></div>
            <div class="col-12 col-md-8 col-lg-9">
                ${SECTIONS.map((x) => x.custom ? `<div data-panel="${x.id}" class="d-none"></div>` : `
                <form data-panel="${x.id}" class="d-none" novalidate>
                    <div class="card-body">
                        <h2 class="mb-1">${x.title}</h2><p class="text-muted mb-4">${x.desc}</p>
                        ${x.blocks.map((b) => `
                            ${b.title ? `<h3 class="card-title mt-4 mb-1">${b.title}</h3>` : ''}
                            ${b.note ? `<p class="text-muted small mb-0">${b.note}</p>` : ''}
                            <div class="row g-3 mt-0 mb-2">${b.fields.map((f) => control(f, ro)).join('')}</div>`).join('')}
                    </div>
                    ${ro ? '' : `<div class="card-footer bg-transparent d-flex align-items-center flex-wrap gap-2">
                        ${x.test ? `<button type="button" class="btn btn-outline-secondary" id="${x.test.id}"><i class="ti ${x.test.icon} me-1"></i>${x.test.label}</button>
                            <span class="small text-muted" data-test-note>Usa le impostazioni salvate.</span>` : ''}
                        <span class="small text-warning ms-auto d-none" data-unsaved><i class="ti ti-point-filled"></i>Modifiche non salvate</span>
                        <button type="button" class="btn btn-link" data-reset disabled>Annulla</button>
                        <button type="submit" class="btn btn-primary" disabled>Salva</button>
                    </div>`}
                </form>`).join('')}
            </div>
        </div></div>`;

    const panel = (id) => container.querySelector(`[data-panel="${id}"]`);
    const forms = SECTIONS.filter((x) => !x.custom).map((x) => ({ sec: x, form: panel(x.id), initial: {} }));
    const rules = rulesEditor(panel('ldap'), groups, ro, () => state.ldap_base_dn || '');

    // --- values: from the server state into the inputs, and what changed since
    function write(entry, keys = null) {
        for (const f of fieldsOf(entry.sec)) {
            if (keys && !keys.includes(f.k)) continue;
            const el = entry.form.elements[f.k];
            if (f.type === 'rules') rules.set(state[f.k]);
            else if (f.type === 'checkbox') el.checked = !!state[f.k];
            else if (f.type === 'password') { el.value = ''; el.placeholder = state[`${f.k}_set`] ? DOTS : ''; }
            else if (f.type === 'color') el.value = hexColor(state[f.k]);
            else el.value = state[f.k] ?? '';
            el.classList?.remove('is-invalid');
            entry.initial[f.k] = read(entry.form, f);
        }
    }
    const changedFields = (entry) => fieldsOf(entry.sec).filter((f) =>
        f.type === 'password' ? read(entry.form, f) !== '' : read(entry.form, f) !== entry.initial[f.k]);

    function refresh(entry) {
        const dirty = changedFields(entry).length > 0;
        container.querySelector(`[data-nav="${entry.sec.id}"] [data-dirty]`).classList.toggle('d-none', !dirty);
        const form = entry.form;
        form.querySelector('[data-unsaved]')?.classList.toggle('d-none', !dirty);
        form.querySelectorAll('[type=submit], [data-reset]').forEach((b) => { b.disabled = !dirty; });
        // The tests read what is saved: not while the section differs from it
        if (entry.sec.test) {
            form.querySelector(`#${entry.sec.test.id}`).disabled = dirty;
            form.querySelector('[data-test-note]').textContent = dirty ? 'Salvare prima di provare.' : 'Usa le impostazioni salvate.';
        }
    }

    for (const entry of forms) {
        write(entry);
        if (ro) continue;
        refresh(entry);
        entry.form.addEventListener('input', () => refresh(entry));
        entry.form.addEventListener('change', () => refresh(entry));
        entry.form.querySelector('[data-reset]').addEventListener('click', () => { write(entry); refresh(entry); });
        entry.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!validateForm(entry.form)) return;
            const fields = changedFields(entry);
            if (!fields.length) return;
            const btn = entry.form.querySelector('[type=submit]');
            btn.disabled = true;
            try {
                state = await apiPatch('/settings/system', Object.fromEntries(fields.map((f) => [f.k, read(entry.form, f)])));
                write(entry, fields.map((f) => f.k));
                showToast(`${entry.sec.title}: impostazioni salvate`, 'success');
            } catch (err) {
                showToast(err.message, 'error', 8000);
            }
            refresh(entry);
        });
    }

    // --- certificates (their own actions, nothing to save)
    const certSec = SECTIONS.find((x) => x.id === 'certs');
    async function refreshCerts() {
        const el = panel('certs');
        el.innerHTML = certPanel(certSec, await apiGet('/settings/ui-certificate').catch(() => null), ro);
        el.querySelector('#ui-cert-upload')?.addEventListener('click', () => uiCertUpload(refreshCerts));
        el.querySelector('#ui-cert-reset')?.addEventListener('click', () => uiCertReset(refreshCerts));
    }
    await refreshCerts();

    container.querySelector('#smtp-test')?.addEventListener('click', async (e) => {
        e.currentTarget.disabled = true;
        try {
            const r = await apiPost('/settings/smtp/test', {});
            showToast(`E-mail di prova inviata a ${r.sent_to.join(', ')}`, 'success', 6000);
        } catch (err) { showToast(err.message, 'error', 8000); }
        e.target.closest('button').disabled = false;
    });
    container.querySelector('#ldap-test')?.addEventListener('click', ldapTest);

    // --- menu
    function show(id) {
        active = id;
        try { sessionStorage.setItem('manager-settings-section', id); } catch { /* private window */ }
        for (const x of SECTIONS) {
            panel(x.id).classList.toggle('d-none', x.id !== id);
            container.querySelector(`[data-nav="${x.id}"]`).classList.toggle('active', x.id === id);
        }
    }
    container.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => show(b.dataset.nav)));
    show(active);
}
