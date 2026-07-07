// Yvonne KMS — Login page logic (v1.4.2)
// Pure vanilla JS, no framework, no inline event handlers (CSP-safe).

(function () {
  'use strict';

  // === Cookie helpers ===
  function getCookie(name) {
    var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : null;
  }

  // === API helpers ===
  function csrfHeader() {
    var token = getCookie('yvonne_csrf');
    if (!token) throw new Error('CSRF cookie missing — refresh the page');
    return token;
  }

  async function jsonFetch(url, opts) {
    var o = opts || {};
    o.headers = Object.assign(
      { 'Content-Type': 'application/json' },
      o.headers || {}
    );
    if (o.credentials === undefined) o.credentials = 'include';
    var resp = await fetch(url, o);
    var ct = resp.headers.get('content-type') || '';
    var body = ct.indexOf('application/json') >= 0 ? await resp.json() : await resp.text();
    return { ok: resp.ok, status: resp.status, body: body };
  }

  // === Device fingerprint (HMAC at server; here we just collect attrs) ===
  function collectDeviceFingerprint() {
    return {
      ua: navigator.userAgent || '',
      lang: navigator.language || (navigator.languages && navigator.languages[0]) || '',
      plat: navigator.platform || '',
      screen: (screen.width || 0) + 'x' + (screen.height || 0) + 'x' + (screen.colorDepth || 0),
      tz: (Intl && Intl.DateTimeFormat().resolvedOptions().timeZone) || ''
    };
  }

  // === Captcha ===
  var state = {
    captchaId: null,
    submitting: false
  };

  async function loadCaptcha() {
    var canvas = document.getElementById('captcha-canvas');
    var ph = document.getElementById('captcha-placeholder');
    if (ph) ph.remove();
    canvas.innerHTML = '<span class="text-mono text-muted text-xs">生成中...</span>';
    var r = await jsonFetch('/admin/api/captcha', { method: 'GET' });
    if (!r.ok) {
      canvas.innerHTML = '<span class="text-red text-xs">加载失败</span>';
      return;
    }
    state.captchaId = r.body.captcha_id;
    document.getElementById('captcha_id').value = r.body.captcha_id;
    canvas.innerHTML = r.body.image;
  }

  // === Show/hide password ===
  function wirePasswordToggle() {
    var btn = document.getElementById('toggle-pw');
    var input = document.getElementById('admin_token');
    var eye = document.getElementById('eye-icon');
    btn.addEventListener('click', function () {
      if (input.type === 'password') {
        input.type = 'text';
        eye.innerHTML = '<use href="/static/icons.svg#eye-off"/>';
        btn.setAttribute('aria-label', '隐藏口令');
      } else {
        input.type = 'password';
        eye.innerHTML = '<use href="/static/icons.svg#eye"/>';
        btn.setAttribute('aria-label', '显示口令');
      }
    });
  }

  // === Alert ===
  function showAlert(kind, text) {
    var el = document.getElementById('alert');
    el.classList.remove('hidden', 'alert-error', 'alert-warning', 'alert-success', 'alert-info');
    el.classList.add('alert-' + kind);
    document.getElementById('alert-text').textContent = text;
  }
  function hideAlert() {
    document.getElementById('alert').classList.add('hidden');
  }

  // === Submit ===
  async function submit(e) {
    e.preventDefault();
    if (state.submitting) return;

    var form = e.target;
    var adminToken = form.admin_token.value.trim();
    var totp = form.totp_code.value.trim();
    var captchaText = form.captcha_text.value.trim();
    var captchaId = form.captcha_id.value;
    var remember = form.remember.checked;

    // Client-side validation
    if (!adminToken) { showAlert('error', '请输入 Admin Token'); return; }
    if (!totp || !/^\d{6}$/.test(totp)) { showAlert('error', '请输入 6 位 TOTP 动态口令'); return; }
    if (!captchaText) { showAlert('error', '请输入图形验证码'); return; }
    if (!captchaId) { showAlert('error', '验证码未加载，请刷新页面'); return; }

    var btn = document.getElementById('btn-submit');
    state.submitting = true;
    btn.disabled = true;
    btn.innerHTML = '<span>登录中...</span>';
    hideAlert();

    try {
      var fpAttrs = collectDeviceFingerprint();
      var resp = await jsonFetch('/admin/api/login', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfHeader() },
        body: JSON.stringify({
          admin_token: adminToken,
          totp_code: totp,
          captcha_id: captchaId,
          captcha_text: captchaText,
          remember: remember,
          device_fp: remember ? (getCookie('yvonne_device') || '') : '',
          device_fingerprint: remember ? fpAttrs : {}
        })
      });

      if (resp.ok) {
        showAlert('success', '登录成功，正在跳转...');
        setTimeout(function () { location.href = '/admin/'; }, 250);
        return;
      }

      // error path
      var err = (resp.body && resp.body.error) || 'unknown';
      var msg = (resp.body && resp.body.msg) || '登录失败';
      var friendly = {
        'locked':    '账号已被锁定 30 分钟（失败次数过多）',
        'captcha':   '验证码错误或已过期',
        'token':     'Admin Token 不正确',
        'totp':      'TOTP 动态口令无效或已使用'
      }[err] || msg;
      showAlert('error', friendly);

      // refresh captcha on any error
      loadCaptcha();
      document.getElementById('captcha_text').value = '';
    } catch (e) {
      showAlert('error', '网络错误：' + e.message);
    } finally {
      state.submitting = false;
      btn.disabled = false;
      btn.innerHTML =
        '<svg class="icon" aria-hidden="true"><use href="/static/icons.svg#key-round"/></svg>' +
        '登&nbsp;&nbsp;录';
    }
  }

  // === Boot ===
  function boot() {
    document.getElementById('login-form').addEventListener('submit', submit);
    document.getElementById('refresh-captcha').addEventListener('click', loadCaptcha);
    wirePasswordToggle();
    loadCaptcha();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
