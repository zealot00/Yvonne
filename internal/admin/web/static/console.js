// Yvonne KMS Console v1.4.2 — 主控台
// 模块化（auth / api / router / idle / page-loaders），原生 JS，CSP 安全。
// 保留 v1.4.0 全部 B 测试 ID：#tokenInput / #nav-* / #stat-* / #btn-* / #keys-* / #crypto-* / #audit-*

(function () {
  'use strict';

  // ===========================================================
  // === Cookie / CSRF ===
  // ===========================================================
  function getCookie(name) {
    var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : null;
  }
  function csrfToken() { return getCookie('yvonne_csrf'); }

  // ===========================================================
  // === API wrapper ===
  // ===========================================================
  async function api(method, path, body) {
    var headers = { 'Content-Type': 'application/json' };
    var token = (document.getElementById('tokenInput') || {}).value
              || localStorage.getItem('yvonne_token')
              || '';
    if (token) headers['Authorization'] = 'Bearer ' + token;

    // CSRF for unsafe methods
    if (method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH') {
      var csrf = csrfToken();
      if (csrf) headers['X-CSRF-Token'] = csrf;
    }

    var opts = { method: method, headers: headers, credentials: 'include' };
    if (body) opts.body = JSON.stringify(body);

    var resp = await fetch(path, opts);
    if (resp.status === 401) {
      // 401 → 跳登录（双轨制：session 失效或 Bearer 失效）
      Auth.redirectToLogin('会话已过期，请重新登录');
      throw new Error('Unauthorized');
    }
    var data;
    try { data = await resp.json(); }
    catch (e) { throw new Error('Invalid JSON response (status ' + resp.status + ')'); }
    if (!data.ok) throw new Error(data.error || data.msg || 'API error');
    return data.data || data;
  }

  // ===========================================================
  // === Auth module ===
  // ===========================================================
  var Auth = {
    async logout() {
      try {
        var csrf = csrfToken();
        await fetch('/admin/api/logout', {
          method: 'POST',
          credentials: 'include',
          headers: csrf ? { 'X-CSRF-Token': csrf } : {}
        });
      } catch (e) { /* 忽略 */ }
      Auth.redirectToLogin();
    },
    redirectToLogin(reason) {
      if (reason) sessionStorage.setItem('yvonne_redirect_reason', reason);
      location.href = '/admin/login';
    }
  };

  // ===========================================================
  // === Router ===
  // ===========================================================
  var Router = {
    current: 'dashboard',
    routes: ['dashboard', 'keys', 'crypto', 'audit', 'mfa'],
    show(name) {
      if (this.routes.indexOf(name) < 0) name = 'dashboard';
      this.current = name;
      // Hide all pages
      var pages = document.querySelectorAll('.page');
      for (var i = 0; i < pages.length; i++) pages[i].classList.add('hidden');
      // Show target
      var target = document.getElementById('page-' + name);
      if (target) target.classList.remove('hidden');
      // Update nav active state
      var navs = document.querySelectorAll('[data-route]');
      for (var j = 0; j < navs.length; j++) {
        navs[j].classList.toggle('active', navs[j].getAttribute('data-route') === name);
      }
      // Lazy load page data
      switch (name) {
        case 'dashboard': loadDashboard(); break;
        case 'keys':      loadKeys(); break;
        case 'audit':     loadAudit(); break;
      }
    }
  };

  // ===========================================================
  // === Page loaders ===
  // ===========================================================
  async function loadDashboard() {
    try {
      var data = await api('GET', '/admin/api/dashboard');
      document.getElementById('stat-keys').textContent = data.key_count || 0;
      document.getElementById('stat-state').textContent = data.state || 'unknown';
      var sealedEl = document.getElementById('stat-sealed');
      sealedEl.textContent = data.sealed ? 'Yes' : 'No';
      sealedEl.className = 'stat-value ' + (data.sealed ? 'text-red' : 'text-green');

      // Session info
      try {
        var sess = await api('GET', '/admin/api/session');
        document.getElementById('session-id').textContent = (sess.user_id || 'admin') + ' · ' + (sess.session_id || sess.id || '-').substring(0, 8);
        Idle.setBaseline(sess.idle_seconds || 1800, sess.hard_cap_seconds || 28800);
      } catch (e) { /* ignore */ }
    } catch (e) {
      document.getElementById('stat-keys').textContent = '!';
      document.getElementById('stat-state').textContent = 'error';
    }
  }

  async function loadKeys() {
    var loading = document.getElementById('keys-loading');
    var wrap = document.getElementById('keys-wrap');
    var body = document.getElementById('keys-body');
    loading.textContent = 'Loading...';
    loading.classList.remove('hidden');
    wrap.classList.add('hidden');
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
      wrap.classList.remove('hidden');
    } catch (e) {
      loading.textContent = 'Error: ' + e.message;
    }
  }

  async function loadAudit() {
    var loading = document.getElementById('audit-loading');
    var wrap = document.getElementById('audit-wrap');
    var body = document.getElementById('audit-body');
    loading.textContent = 'No audit entries (use POST /api/v1/audit/query with Bearer token).';
    loading.classList.remove('hidden');
    wrap.classList.add('hidden');
    body.innerHTML = '';
  }

  async function doEncrypt() {
    var keyId = document.getElementById('crypto-keyid').value.trim();
    var data = document.getElementById('crypto-data').value;
    if (!keyId || !data) return;
    var resultDiv = document.getElementById('crypto-result');
    var output = document.getElementById('crypto-output');
    try {
      var resp = await api('POST', '/admin/api/crypto/encrypt', {
        key_id: keyId,
        plaintext: btoa(unescape(encodeURIComponent(data)))
      });
      output.textContent = JSON.stringify(resp, null, 2);
      resultDiv.classList.remove('hidden');
    } catch (e) {
      output.textContent = 'Error: ' + e.message;
      resultDiv.classList.remove('hidden');
    }
  }

  async function doDecrypt() {
    var keyId = document.getElementById('crypto-keyid').value.trim();
    var data = document.getElementById('crypto-data').value;
    if (!keyId || !data) return;
    var resultDiv = document.getElementById('crypto-result');
    var output = document.getElementById('crypto-output');
    try {
      var resp = await api('POST', '/admin/api/crypto/decrypt', {
        key_id: keyId,
        ciphertext: data
      });
      var plain = resp.plaintext
        ? decodeURIComponent(escape(atob(resp.plaintext)))
        : '';
      output.textContent = 'Plaintext: ' + plain + '\n\n' + JSON.stringify(resp, null, 2);
      resultDiv.classList.remove('hidden');
    } catch (e) {
      output.textContent = 'Error: ' + e.message;
      resultDiv.classList.remove('hidden');
    }
  }

  // ===========================================================
  // === Idle / Hard-cap timer (30 min / 8 h) ===
  // ===========================================================
  var Idle = {
    idleSeconds: 1800,
    hardCapSeconds: 28800,
    warningThreshold: 60,   // 60s 前弹窗
    activityTimer: null,
    countdownTimer: null,
    setBaseline(idleSec, hardSec) {
      this.idleSeconds = idleSec;
      this.hardCapSeconds = hardSec;
      this.updateCountdown();
    },
    reset() {
      this.idleSeconds = 1800;
      // 后端 idle 是服务器测的，前端只做 UI 提示
    },
    updateCountdown() {
      var el = document.getElementById('idle-countdown');
      if (!el) return;
      var mm = Math.floor(this.idleSeconds / 60);
      var ss = this.idleSeconds % 60;
      el.textContent = (mm < 10 ? '0' : '') + mm + ':' + (ss < 10 ? '0' : '') + ss;
    },
    start() {
      // 1Hz 倒计时（仅 UI 提示；实际 idle 校验在后端）
      this.countdownTimer = setInterval(() => {
        if (this.idleSeconds > 0) this.idleSeconds--;
        if (this.hardCapSeconds > 0) this.hardCapSeconds--;
        this.updateCountdown();
        if (this.idleSeconds === this.warningThreshold) this.showWarning();
        if (this.idleSeconds <= 0) {
          clearInterval(this.countdownTimer);
          Auth.redirectToLogin('会话已过期（30 分钟无操作）');
        }
      }, 1000);
    },
    showWarning() {
      var host = document.getElementById('modal-host');
      if (!host) return;
      host.innerHTML =
        '<div class="modal-backdrop" role="dialog" aria-labelledby="idle-warn-title">' +
        '  <div class="modal">' +
        '    <div class="modal-title" id="idle-warn-title">' +
        '      <svg class="icon" aria-hidden="true"><use href="/static/icons.svg#clock"/></svg>' +
        '      会话即将到期' +
        '    </div>' +
        '    <div class="modal-body">您已 29 分钟无操作。<br>再过 60 秒会话将自动注销。</div>' +
        '    <div class="modal-actions">' +
        '      <button class="btn btn-secondary" id="modal-logout">立即注销</button>' +
        '      <button class="btn btn-primary" id="modal-continue">继续操作</button>' +
        '    </div>' +
        '  </div>' +
        '</div>';
      document.getElementById('modal-logout').addEventListener('click', () => Auth.logout());
      document.getElementById('modal-continue').addEventListener('click', () => {
        host.innerHTML = '';
        // 触发一次后端调用刷新 idle（dashboard reload 即触发）
        loadDashboard();
      });
    }
  };

  // ===========================================================
  // === Wire up ===
  // ===========================================================
  function boot() {
    // Token input — 保留 v1.4.0 兼容（localStorage）
    var saved = localStorage.getItem('yvonne_token');
    if (saved) document.getElementById('tokenInput').value = saved;
    document.getElementById('tokenInput').addEventListener('input', function (e) {
      localStorage.setItem('yvonne_token', e.target.value);
    });

    // Nav
    var navMap = {
      'nav-dashboard': 'dashboard',
      'nav-keys':      'keys',
      'nav-crypto':    'crypto',
      'nav-audit':     'audit',
      'nav-mfa':       'mfa'
    };
    Object.keys(navMap).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener('click', function (e) {
        e.preventDefault();
        Router.show(navMap[id]);
      });
    });

    // Buttons
    document.getElementById('btn-refresh-keys').addEventListener('click', loadKeys);
    document.getElementById('btn-encrypt').addEventListener('click', doEncrypt);
    document.getElementById('btn-decrypt').addEventListener('click', doDecrypt);
    document.getElementById('btn-logout').addEventListener('click', function () {
      if (confirm('确定注销当前会话？')) Auth.logout();
    });

    // Default route
    Router.show('dashboard');
    Idle.start();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
