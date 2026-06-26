// Yvonne KMS - 管理页面 SPA 入口。
// 仅做最基本路由 + 视图渲染，不引入任何第三方框架。

const API = {
  sealStatus: '/admin/api/seal-status',
  seal: '/admin/api/seal',
  unseal: '/admin/api/unseal',
};

const state = {
  seal: null, // {sealed, state, total_shares, threshold}
  unsealProgress: 0, // 已提交的 share 数
};

// ----------------------------- 工具函数 -----------------------------

// getAdminToken 从 URL hash 或 localStorage 读取 admin token（BUG-10 修复）。
function getAdminToken() {
  // 优先从 URL hash 读取（#token=xxx），其次 localStorage。
  const hashMatch = window.location.hash.match(/token=([^&]+)/);
  if (hashMatch) {
    const token = decodeURIComponent(hashMatch[1]);
    localStorage.setItem('yvonne_admin_token', token);
    // 清除 hash 中的 token（防泄漏到日志/书签）。
    window.location.hash = '';
    return token;
  }
  return localStorage.getItem('yvonne_admin_token') || '';
}

async function fetchJSON(url, opts = {}) {
  const token = getAdminToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = 'Bearer ' + token;
  }
  const res = await fetch(url, {
    headers: { ...headers, ...(opts.headers || {}) },
    ...opts,
  });
  // 401 时清除 token 并提示重新输入。
  if (res.status === 401) {
    localStorage.removeItem('yvonne_admin_token');
    const token = prompt('Admin Token required:');
    if (token) {
      localStorage.setItem('yvonne_admin_token', token);
      return fetchJSON(url, opts); // 重试一次。
    }
    throw new Error('unauthorized');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function toast(msg, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'html') node.innerHTML = v;
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

// ----------------------------- 状态同步 -----------------------------

async function refreshSealStatus() {
  try {
    const data = await fetchJSON(API.sealStatus);
    state.seal = data;
    if (!data.sealed) {
      state.unsealProgress = 0;
    }
    updateStatePill();
  } catch (e) {
    state.seal = null;
    updateStatePill();
  }
}

function updateStatePill() {
  const pill = document.getElementById('state-pill');
  if (!state.seal) {
    pill.textContent = 'unreachable';
    pill.className = 'state-pill sealed';
    return;
  }
  pill.textContent = state.seal.state;
  pill.className = 'state-pill ' + (state.seal.sealed ? 'sealed' : 'unsealed');
}

// ----------------------------- 视图 -----------------------------

function renderOverview() {
  const root = document.getElementById('view');
  root.innerHTML = '';

  if (!state.seal) {
    root.appendChild(el('div', { class: 'card' }, [
      el('h2', {}, 'KMS 状态'),
      el('div', { class: 'empty' }, '无法连接 KMS 后端'),
    ]));
    return;
  }

  const s = state.seal;
  root.appendChild(el('div', { class: 'card' }, [
    el('h2', {}, 'KMS 状态'),
    el('div', { class: 'kv' }, [
      el('div', { class: 'k' }, 'State'),
      el('div', { class: 'v' }, s.state),
      el('div', { class: 'k' }, 'Sealed'),
      el('div', { class: 'v' }, String(s.sealed)),
      el('div', { class: 'k' }, 'Threshold'),
      el('div', { class: 'v' }, `${s.threshold} / ${s.total_shares}`),
    ]),
  ]));

  if (!s.sealed) {
    root.appendChild(el('div', { class: 'card' }, [
      el('h2', {}, '危险操作'),
      el('div', { class: 'note' }, '点击下方按钮会立即清零内存中的 Master Key 并拒绝所有加解密请求。'),
      el('div', { class: 'btn-row' }, [
        el('button', { class: 'danger', onclick: doSeal }, '立即重新封印 (Seal)'),
      ]),
    ]));
  }
}

async function doSeal() {
  if (!confirm('确认重新封印？所有加解密 API 将立即不可用。')) return;
  try {
    await fetchJSON(API.seal, { method: 'POST' });
    toast('已封印', 'ok');
  } catch (e) {
    toast('封印失败: ' + e.message, 'error');
  }
  await refreshSealStatus();
  renderOverview();
}

function renderUnseal() {
  const root = document.getElementById('view');
  root.innerHTML = '';

  if (!state.seal) {
    root.appendChild(el('div', { class: 'card' }, [el('h2', {}, 'Unseal'), el('div', { class: 'empty' }, '无法连接 KMS 后端')]));
    return;
  }

  if (!state.seal.sealed) {
    root.appendChild(el('div', { class: 'card' }, [
      el('h2', {}, 'Unseal'),
      el('div', { class: 'empty' }, '当前已 Unsealed，无需操作。'),
    ]));
    return;
  }

  const need = state.seal.threshold;
  const remaining = need - state.unsealProgress;

  const card = el('div', { class: 'card' }, [
    el('h2', {}, 'Unseal (Shamir 重组)'),
    el('div', { class: 'note' }, `门限 ${need} / ${state.seal.total_shares}。已提交 ${state.unsealProgress} 份，还需 ${remaining} 份。逐份提交 Share（hex 或 base64）。`),
  ]);

  const ta = el('textarea', {
    placeholder: `Share #${state.unsealProgress + 1} (hex 或 base64)`,
    id: 'share-input',
    rows: '4',
  });
  card.appendChild(ta);

  const btnRow = el('div', { class: 'btn-row' }, [
    el('button', { onclick: () => doUnsealSingle(ta) }, `提交 Share #${state.unsealProgress + 1}`),
  ]);
  card.appendChild(btnRow);

  // 进度指示器。
  const progress = el('div', { class: 'kv' });
  for (let i = 0; i < need; i++) {
    progress.appendChild(el('div', { class: 'k' }, `Share #${i + 1}`));
    if (i < state.unsealProgress) {
      progress.appendChild(el('div', { class: 'v', style: 'color: green' }, '✓ 已提交'));
    } else {
      progress.appendChild(el('div', { class: 'v', style: 'color: #888' }, '○ 待提交'));
    }
  }
  card.appendChild(progress);

  root.appendChild(card);
}

async function doUnsealSingle(textarea) {
  const shareVal = textarea.value.trim();
  if (!shareVal) {
    toast('请输入 Share', 'error');
    return;
  }

  // 尝试 hex 解码，失败则当作 base64。
  let shareBytes;
  try {
    // hex 解码。
    const cleanHex = shareVal.replace(/\s+/g, '');
    if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length % 2 === 0) {
      shareBytes = cleanHex;
    } else {
      // 当作 base64。
      shareBytes = shareVal;
    }
  } catch {
    shareBytes = shareVal;
  }

  try {
    const resp = await fetchJSON(API.unseal, {
      method: 'POST',
      body: JSON.stringify({ share: shareBytes }),
    });

    if (resp.unsealed) {
      toast('解封成功！', 'ok');
      state.unsealProgress = 0;
    } else {
      state.unsealProgress++;
      toast(`Share 已接受 (${state.unsealProgress}/${state.seal.threshold})`, 'ok');
    }

    // 清空输入框（阅后即焚）。
    textarea.value = '';
  } catch (e) {
    toast('Unseal 失败: ' + e.message, 'error');
  }

  await refreshSealStatus();
  renderUnseal();
}

function renderKeys() {
  const root = document.getElementById('view');
  root.innerHTML = '';

  root.appendChild(el('div', { class: 'card' }, [
    el('h2', {}, '密钥列表'),
    el('div', { class: 'note' }, '密钥管理请通过 KMS API 操作。此处仅展示状态概览。'),
    el('div', { class: 'empty' }, '通过 API 创建密钥后，此处将展示密钥列表。'),
  ]));
}

// ----------------------------- 路由 -----------------------------

const routes = {
  overview: renderOverview,
  unseal: renderUnseal,
  keys: renderKeys,
};

function router() {
  const hash = location.hash.replace(/^#\/?/, '') || 'overview';
  const name = routes[hash] ? hash : 'overview';
  document.querySelectorAll('.nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.route === name);
  });
  (routes[name] || renderOverview)();
}

window.addEventListener('hashchange', router);
window.addEventListener('DOMContentLoaded', async () => {
  await refreshSealStatus();
  router();
  setInterval(async () => {
    await refreshSealStatus();
  }, 5000);
});
