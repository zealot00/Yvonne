// Yvonne KMS Console — 纯原生 JS（无框架、无内联事件）
// 所有事件绑定通过 addEventListener（CSP 安全）

document.addEventListener('DOMContentLoaded', function() {
    var saved = localStorage.getItem('yvonne_token');
    if (saved) document.getElementById('tokenInput').value = saved;

    document.getElementById('tokenInput').addEventListener('input', function() {
        localStorage.setItem('yvonne_token', this.value);
    });

    document.getElementById('nav-dashboard').addEventListener('click', function() { showPage('dashboard'); });
    document.getElementById('nav-keys').addEventListener('click', function() { showPage('keys'); });
    document.getElementById('nav-crypto').addEventListener('click', function() { showPage('crypto'); });
    document.getElementById('nav-audit').addEventListener('click', function() { showPage('audit'); });
    document.getElementById('nav-mfa').addEventListener('click', function() { showPage('mfa'); });

    document.getElementById('btn-refresh-keys').addEventListener('click', loadKeys);
    document.getElementById('btn-encrypt').addEventListener('click', doEncrypt);
    document.getElementById('btn-decrypt').addEventListener('click', doDecrypt);

    showPage('dashboard');
});

function getToken() {
    return document.getElementById('tokenInput').value || localStorage.getItem('yvonne_token') || '';
}

async function api(method, path, body) {
    var headers = { 'Content-Type': 'application/json' };
    var token = getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    var opts = { method: method, headers: headers };
    if (body) opts.body = JSON.stringify(body);
    var resp = await fetch(path, opts);
    var data = await resp.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');
    return data.data || data;
}

function showPage(name) {
    var pages = document.querySelectorAll('.page');
    for (var i = 0; i < pages.length; i++) pages[i].classList.add('hidden');
    var page = document.getElementById('page-' + name);
    if (page) page.classList.remove('hidden');
    if (name === 'dashboard') loadDashboard();
    if (name === 'keys') loadKeys();
    if (name === 'audit') loadAudit();
}

async function loadDashboard() {
    try {
        var data = await api('GET', '/admin/api/dashboard');
        document.getElementById('stat-keys').textContent = data.key_count || 0;
        document.getElementById('stat-state').textContent = data.state || 'unknown';
        var sealedEl = document.getElementById('stat-sealed');
        sealedEl.textContent = data.sealed ? 'Yes' : 'No';
        sealedEl.className = 'stat-value ' + (data.sealed ? 'text-red' : 'text-green');
    } catch (e) {
        document.getElementById('stat-keys').textContent = '!';
        document.getElementById('stat-state').textContent = 'error';
    }
}

async function loadKeys() {
    var loading = document.getElementById('keys-loading');
    var table = document.getElementById('keys-table');
    var body = document.getElementById('keys-body');
    loading.textContent = 'Loading...';
    loading.classList.remove('hidden');
    table.classList.add('hidden');
    body.innerHTML = '';
    try {
        var data = await api('GET', '/admin/api/keys');
        var keys = data.keys || [];
        if (keys.length === 0) {
            loading.textContent = 'No keys found.';
            return;
        }
        for (var i = 0; i < keys.length; i++) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.className = 'mono';
            td.textContent = keys[i].key_id || keys[i].KeyID || '-';
            tr.appendChild(td);
            body.appendChild(tr);
        }
        loading.classList.add('hidden');
        table.classList.remove('hidden');
    } catch (e) {
        loading.textContent = 'Error: ' + e.message;
    }
}

async function doEncrypt() {
    var keyId = document.getElementById('crypto-keyid').value;
    var data = document.getElementById('crypto-data').value;
    if (!keyId || !data) return;
    var resultDiv = document.getElementById('crypto-result');
    var output = document.getElementById('crypto-output');
    try {
        var resp = await api('POST', '/admin/api/crypto/encrypt', {
            key_id: keyId,
            plaintext: btoa(data)
        });
        output.textContent = JSON.stringify(resp, null, 2);
        resultDiv.classList.remove('hidden');
    } catch (e) {
        output.textContent = 'Error: ' + e.message;
        resultDiv.classList.remove('hidden');
    }
}

async function doDecrypt() {
    var keyId = document.getElementById('crypto-keyid').value;
    var data = document.getElementById('crypto-data').value;
    if (!keyId || !data) return;
    var resultDiv = document.getElementById('crypto-result');
    var output = document.getElementById('crypto-output');
    try {
        var resp = await api('POST', '/admin/api/crypto/decrypt', {
            key_id: keyId,
            ciphertext: data
        });
        var plain = atob(resp.plaintext || '');
        output.textContent = 'Plaintext: ' + plain + '\n\n' + JSON.stringify(resp, null, 2);
        resultDiv.classList.remove('hidden');
    } catch (e) {
        output.textContent = 'Error: ' + e.message;
        resultDiv.classList.remove('hidden');
    }
}

async function loadAudit() {
    var loading = document.getElementById('audit-loading');
    var table = document.getElementById('audit-table');
    var body = document.getElementById('audit-body');
    loading.textContent = 'No audit entries (use POST /api/v1/audit/query with Bearer token to query).';
    loading.classList.remove('hidden');
    table.classList.add('hidden');
    body.innerHTML = '';
}
