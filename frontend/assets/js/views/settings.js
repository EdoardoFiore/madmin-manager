/**
 * MADMIN Manager - Settings.
 */
import { apiGet, apiPatch, apiPost, apiDelete } from '../api.js';
import { escapeHtml, showToast } from '../utils.js';
import { checkPermission } from '../app.js';
import { formModal, formData, field, notice, confirmAction, fmtDate, otpField } from './manager-common.js';

const FIELDS = [
    ['Generale', [
        ['company_name', 'Nome', 'text'],
        ['primary_color', 'Colore principale', 'text'],
        ['default_language', 'Lingua predefinita (it/en)', 'text'],
        ['password_max_age_days', 'Scadenza password (giorni, 0 = mai)', 'number'],
    ]],
    ['Istanze', [
        ['agent_url', 'URL agent (https://host:8443), scritto nei token di enrollment', 'text'],
        ['support_host', 'Host per le porte di supporto (vuoto = host dell\'URL agent)', 'text'],
        ['support_port_min', 'Prima porta di supporto', 'number'],
        ['support_port_max', 'Ultima porta di supporto', 'number'],
    ]],
    ['Registrazione senza token', [
        ['registration_enabled', 'Ammessa (le richieste vanno approvate in Enrollment)', 'checkbox'],
        ['registration_allowed_cidrs', 'Solo da queste reti (separate da virgola, vuoto = tutte)', 'text'],
        ['registration_ttl_days', 'Scadenza delle richieste (giorni)', 'number'],
        ['registration_max_pending', 'Massimo richieste in attesa', 'number'],
    ]],
    ['Agent delle istanze (applicato alla connessione successiva)', [
        ['agent_heartbeat_interval', 'Heartbeat ogni (secondi, 30-600)', 'number'],
        ['agent_facts_interval', 'Controllo dei dati dell\'istanza ogni (secondi, 60-3600)', 'number'],
        ['agent_backoff_max', 'Attesa massima tra due riconnessioni (secondi, 30-900)', 'number'],
    ]],
    ['Release', [
        ['release_keys', 'Chiavi pubbliche di firma (PEM, una o più): una release caricata deve essere firmata da una di queste. Vuoto = non verificata qui (le istanze la verificano sempre)', 'textarea'],
    ]],
    ['Aggiornamenti automatici delle istanze', [
        ['autoupdate_time', 'Ora (ogni giorno: solo gli aggiornamenti di sicurezza della versione di Ubuntu installata, mai gli aggiornamenti normali né un\'altra versione di Ubuntu; poi riavvio dei servizi che li usano, mai della macchina). Un gruppo può avere la sua', 'time'],
        ['autoupdate_tz', 'Fuso orario (es. Europe/Rome)', 'text'],
        ['autoupdate_randomize', 'Ritardo casuale massimo (minuti, 0-180): le istanze non si aggiornano tutte nello stesso istante', 'number'],
    ]],
    ['Notifiche e-mail', [
        ['smtp_host', 'Server SMTP (vuoto = nessuna e-mail, restano i contatori nel menu)', 'text'],
        ['smtp_port', 'Porta', 'number'],
        ['smtp_encryption', 'Cifratura (none, tls = STARTTLS, ssl)', 'text'],
        ['smtp_username', 'Utente', 'text'],
        ['smtp_password', 'Password (vuoto = invariata)', 'password'],
        ['smtp_from', 'Mittente', 'text'],
        ['notify_to', 'Destinatari (separati da virgola; vuoto = i superuser con e-mail)', 'text'],
    ]],
    ['Utenti LDAP / Active Directory', [
        ['ldap_enabled', 'Login con utenti LDAP (gli utenti locali restano validi)', 'checkbox'],
        ['ldap_url', 'Server (ldaps://host:636, oppure ldap://host con StartTLS)', 'text'],
        ['ldap_bind_dn', 'Account di servizio (DN) per le ricerche', 'text'],
        ['ldap_bind_password', 'Password dell\'account di servizio (vuoto = invariata)', 'password'],
        ['ldap_base_dn', 'Base di ricerca', 'text'],
        ['ldap_user_filter', 'Filtro utente ({username} = nome inserito al login)', 'text'],
        ['ldap_ca_pem', 'CA del server LDAP (PEM; vuoto = CA di sistema)', 'textarea'],
        ['ldap_mappings', 'Gruppi LDAP → ruolo (JSON, vince il primo): [{"group": "cn=...,dc=...", "role": "superuser|partner|customer", "access": "rw|ro", "group_id": "<id gruppo del manager>"}]', 'textarea'],
    ]],
    ['Backup e licenze', [
        ['backup_interval_hours', 'Backup pianificati ogni (ore, 0 = disattivati)', 'number'],
        ['backup_retention', 'Backup conservati per istanza', 'number'],
        ['license_validity_days', 'Durata di un token di licenza (giorni)', 'number'],
    ]],
];

// The certificate of the UI port only: the instances' port (8443) always uses
// the one issued by the manager CA.
function uiCertCard(c, ro) {
    if (!c) return '';
    const days = c.days_left;
    const tone = days == null ? 'secondary' : days < 15 ? 'danger' : days < 30 ? 'warning' : 'success';
    const details = c.not_after ? `
        <div class="mb-2"><div class="small text-muted">Valido per</div>
            <div class="font-monospace small text-break">${(c.names || []).map(escapeHtml).join(', ') || '-'}</div></div>
        <div class="mb-2"><div class="small text-muted">Emesso da</div><div class="small text-break">${escapeHtml(c.issuer || '-')}</div></div>
        <div class="mb-3"><div class="small text-muted">Scadenza</div>
            <div class="small">${fmtDate(c.not_after)} <span class="badge bg-${tone}-lt ms-1">${days < 0 ? 'scaduto' : `${days} giorni`}</span></div></div>` : '';
    return `<div class="col-lg-6 col-xl-3"><div class="card"><div class="card-header"><h3 class="card-title">Certificato della UI</h3></div>
        <div class="card-body">
            <div class="mb-3">${c.custom
                ? '<span class="badge bg-success-lt">Proprio</span>'
                : '<span class="badge bg-secondary-lt">Interno (CA del manager)</span>'}
                <div class="form-hint">${c.custom
                    ? 'Non si rinnova da solo: caricare il nuovo prima della scadenza.'
                    : 'I browser non conoscono la CA del manager e mostrano un avviso: caricare un certificato proprio per toglierlo.'}
                    Riguarda solo la UI, non la porta delle istanze.</div></div>
            ${details}
            ${c.installed ? '' : notice('warning', '', ['Non gestito da questa installazione: rieseguire <code>setup-manager.sh</code> di questa versione.'])}
            ${ro || !c.installed ? '' : `<div class="btn-list">
                <button type="button" class="btn btn-outline-primary btn-sm" id="ui-cert-upload"><i class="ti ti-upload me-1"></i>Carica certificato</button>
                ${c.custom ? '<button type="button" class="btn btn-outline-secondary btn-sm" id="ui-cert-reset">Torna a quello interno</button>' : ''}
            </div>`}
        </div></div></div>`;
}

function uiCertUpload(container) {
    const host = location.hostname;
    formModal('Certificato della UI', `
        ${notice('info', '', [
            ['ti-world', 'Vale solo per la UI. La porta delle istanze resta sul certificato della CA del manager.'],
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
        showToast('Certificato della UI installato', 'success', 6000);
        render(container);
    }, { submitText: 'Installa', icon: 'ti-certificate' });
}

async function uiCertReset(container) {
    const ok = await confirmAction({
        title: 'Tornare al certificato interno?', tone: 'warning', confirmText: 'Ripristina', icon: 'ti-certificate',
        items: ['Il certificato caricato e la sua chiave vengono eliminati dal manager.',
                'La UI torna al certificato emesso dalla CA del manager: i browser mostreranno di nuovo l\'avviso.'],
    });
    if (!ok) return;
    try {
        await apiDelete('/settings/ui-certificate');
        showToast('Certificato interno ripristinato', 'success');
        render(container);
    } catch (err) { showToast(err.message, 'error', 8000); }
}

export async function render(container) {
    const s = await apiGet('/settings/system');
    const ro = !checkPermission('manager.manage');
    const uiCert = await apiGet('/settings/ui-certificate').catch(() => null);
    container.innerHTML = `
        <form id="manager-settings" class="row row-cards">
            ${FIELDS.map(([title, fields]) => `
                <div class="col-lg-6 col-xl-3"><div class="card"><div class="card-header"><h3 class="card-title">${title}</h3></div>
                <div class="card-body">${fields.map(([k, label, type]) => type === 'textarea' ? `
                    <div class="mb-3"><label class="form-label">${label}</label>
                    <textarea name="${k}" class="form-control font-monospace small" rows="6" ${ro ? 'disabled' : ''}>${escapeHtml(s[k] ?? '')}</textarea></div>` : type === 'checkbox' ? `
                    <label class="form-check mb-3"><input name="${k}" type="checkbox" class="form-check-input" ${s[k] ? 'checked' : ''} ${ro ? 'disabled' : ''}>
                    <span class="form-check-label">${label}</span></label>` : `
                    <div class="mb-3"><label class="form-label">${label}</label>
                    <input name="${k}" type="${type}" class="form-control" value="${type === 'password' ? '' : escapeHtml(s[k] ?? '')}"
                        ${type === 'password' ? `autocomplete="new-password" placeholder="${s[`${k}_set`] ? '••••••••' : ''}"` : ''} ${ro ? 'disabled' : ''}></div>`).join('')}
                ${title === 'Notifiche e-mail' && !ro ? '<button type="button" class="btn btn-outline-secondary btn-sm" id="smtp-test">Invia e-mail di prova</button>' : ''}
                ${title.startsWith('Utenti LDAP') && !ro ? '<button type="button" class="btn btn-outline-secondary btn-sm" id="ldap-test">Prova un login</button>' : ''}
                </div></div></div>`).join('')}
            ${uiCertCard(uiCert, ro)}
            ${ro ? '' : '<div class="col-12"><button class="btn btn-primary">Salva</button></div>'}
        </form>`;
    container.querySelector('#ui-cert-upload')?.addEventListener('click', () => uiCertUpload(container));
    container.querySelector('#ui-cert-reset')?.addEventListener('click', () => uiCertReset(container));
    container.querySelector('#smtp-test')?.addEventListener('click', async () => {
        try {
            const r = await apiPost('/settings/smtp/test', {});
            showToast(`E-mail di prova inviata a ${r.sent_to.join(', ')}`, 'success', 6000);
        } catch (err) { showToast(err.message, 'error', 8000); }
    });
    container.querySelector('#ldap-test')?.addEventListener('click', () => {
        const el = formModal('Prova login LDAP', `
            ${notice('info', '', [['ti-info-circle', 'Usa le impostazioni <b>salvate</b>; non crea l\'utente, mostra cosa otterrebbe al login.']])}
            ${field('username', 'Utente', { required: true, maxlength: 100, attrs: 'autocomplete="off"', example: 'mario.rossi' })}
            ${field('password', 'Password', { type: 'password', required: true, attrs: 'autocomplete="new-password"' })}
            <div id="ldap-result"></div>`,
        async (form) => {
            const box = el.querySelector('#ldap-result');
            const r = await apiPost('/settings/ldap/test', formData(form));
            const m = r.mapping;
            box.innerHTML = notice(m ? 'success' : 'warning', m ? 'Login consentito' : 'Login rifiutato: nessun gruppo mappato', [
                ['ti-id', `<span class="font-monospace small">${escapeHtml(r.dn)}</span>`],
                m ? ['ti-user-shield', `Ruolo <b>${escapeHtml(m.role)}</b>, accesso <b>${escapeHtml(m.access)}</b>${m.group_id ? `, gruppo <span class="font-monospace">${escapeHtml(m.group_id)}</span>` : ''}`] : null,
                ['ti-users-group', `Gruppi: ${r.groups.map(g => `<span class="font-monospace small">${escapeHtml(g)}</span>`).join(', ') || 'nessuno'}`]]);
            return false;
        }, { submitText: 'Prova', icon: 'ti-plug-connected' });
    });
    container.querySelector('#manager-settings').addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = {};
        for (const [, fields] of FIELDS) {
            for (const [k, , type] of fields) {
                const input = e.target.elements[k];
                if (type === 'checkbox') { body[k] = input.checked; continue; }
                const v = input.value.trim();
                if (type === 'password' && !v) continue;
                body[k] = type === 'number' ? Number(v) : v;
            }
        }
        try {
            await apiPatch('/settings/system', body);
            showToast('Impostazioni salvate', 'success');
        } catch (err) {
            showToast(err.message, 'error', 6000);
        }
    });
}
