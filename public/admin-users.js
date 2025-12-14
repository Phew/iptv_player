const state = {
  users: [],
  search: '',
  role: '',
  stats: { total: 0, limit: 0 },
  sessions: [],
  siteName: 'theater.cat',
};

const qs = (id) => document.getElementById(id);

const fetchJson = async (url, options = {}) => {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'include',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = data.error || 'Request failed';
    throw new Error(error);
  }
  return data;
};

const setStatus = (el, message, isError = false) => {
  if (!el) return;
  el.textContent = message || '';
  el.style.color = isError ? '#ff9fbf' : 'var(--accent)';
};

const applySiteName = (name) => {
  if (!name) return;
  state.siteName = name;
  const titleEl = qs('site-title');
  if (titleEl) titleEl.textContent = name;
  const pageTitle = qs('site-page-title');
  if (pageTitle) pageTitle.textContent = `${name} · Users`;
  document.title = `${name} · Users`;
};

const ensureAdmin = async () => {
  try {
    const data = await fetchJson('/api/auth/me');
    if (!data.user || data.user.role !== 'admin') throw new Error('Not admin');
  } catch (err) {
    console.warn('Admin users auth check failed', err?.message || err);
    setStatus(qs('users-status'), 'Sign in again to manage users.', true);
  }
};

const renderUsers = () => {
  const list = qs('users-list');
  list.innerHTML = '';
  const term = state.search.toLowerCase();
  const filtered = state.users.filter((u) => {
    if (state.role && u.role !== state.role) return false;
    return u.username.toLowerCase().includes(term);
  });
  if (!filtered.length) {
    list.innerHTML = '<p class="muted tiny">No users.</p>';
    return;
  }
  filtered.forEach((u) => {
    const session = state.sessions.find((s) => s.user === u.username);
    const online = !!session;
    const statusText = online
      ? `Online · ${session.page || 'home'}${session.channelName ? ` · ${session.channelName}` : ''}`
      : 'Offline';
    const row = document.createElement('div');
    row.className = 'playlist';
    row.innerHTML = `
      <div class="name">${u.username}</div>
      <div class="meta">
        <span>${u.role}</span>
        <span class="${online ? '' : 'muted'} tiny">${statusText}</span>
      </div>
      <div class="meta">
        <label class="field">
          <span class="tiny muted">Role</span>
          <select data-id="${u.id}" class="user-role">
            <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>viewer</option>
            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option>
          </select>
        </label>
        <label class="field">
          <span class="tiny muted">Reset password</span>
          <input type="password" data-id="${u.id}" class="user-pass" placeholder="New password">
        </label>
        <div class="meta">
          <button class="ghost-btn save-user" data-id="${u.id}">Save</button>
          <button class="ghost-btn danger delete-user" data-id="${u.id}">Delete</button>
        </div>
      </div>
    `;
    list.appendChild(row);
  });

  list.querySelectorAll('.save-user').forEach((btn) => {
    btn.addEventListener('click', () => saveUser(btn.dataset.id));
  });
  list.querySelectorAll('.delete-user').forEach((btn) => {
    btn.addEventListener('click', () => deleteUser(btn.dataset.id));
  });
};

const loadUsers = async () => {
  setStatus(qs('users-status'), 'Loading…');
  try {
    const [users, stats] = await Promise.all([
      fetchJson('/api/admin/users'),
      fetchJson('/api/watch/stats'),
    ]);
    state.users = users.users || [];
    state.stats = stats || { total: 0, limit: 0 };
    state.sessions = stats.sessions || [];
    renderUsers();
    renderUserStats();
    setStatus(qs('users-status'), '');
  } catch (err) {
    setStatus(qs('users-status'), err.message, true);
  }
};

const importJellyfinUsers = async () => {
  setStatus(qs('import-status'), 'Importing Jellyfin users…');
  try {
    const result = await fetchJson('/api/admin/users/import-jellyfin', { method: 'POST' });
    const message = `Imported ${result.created || 0} new, ${result.updated || 0} updated, ${result.skipped || 0} skipped`;
    setStatus(qs('import-status'), message);
    await loadUsers();
  } catch (err) {
    setStatus(qs('import-status'), err.message, true);
  }
};

const saveUser = async (id) => {
  const roleSel = document.querySelector(`select.user-role[data-id="${id}"]`);
  const passInput = document.querySelector(`input.user-pass[data-id="${id}"]`);
  if (!roleSel) return;
  const payload = {};
  if (roleSel.value) payload.role = roleSel.value;
  if (passInput && passInput.value) payload.password = passInput.value;
  if (!payload.role && !payload.password) return;
  setStatus(qs('users-status'), 'Saving…');
  try {
    await fetchJson(`/api/admin/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
    if (passInput) passInput.value = '';
    await loadUsers();
  } catch (err) {
    setStatus(qs('users-status'), err.message, true);
  }
};

const renderUserStats = () => {
  const el = qs('users-stats');
  if (!el) return;
  const total = state.sessions.length || state.stats.total || 0;
  el.textContent = `Connections: ${total}/${state.stats.limit || 'n/a'}`;
};

const deleteUser = async (id) => {
  if (!window.confirm('Delete this user?')) return;
  setStatus(qs('users-status'), 'Deleting…');
  try {
    await fetchJson(`/api/admin/users/${id}`, { method: 'DELETE' });
    await loadUsers();
  } catch (err) {
    setStatus(qs('users-status'), err.message, true);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  ensureAdmin().then(async () => {
    try {
      const settings = await fetchJson('/api/settings');
      if (settings?.siteName) applySiteName(settings.siteName);
    } catch (_e) {
      // ignore
    }
    await loadUsers();
  });

  qs('admin-logout').addEventListener('click', async () => {
    await fetchJson('/api/auth/logout', { method: 'POST' }).catch(() => {});
    window.location.href = '/';
  });

  qs('user-search').addEventListener('input', (e) => {
    state.search = e.target.value;
    renderUsers();
  });
  qs('user-role-filter').addEventListener('change', (e) => {
    state.role = e.target.value;
    renderUsers();
  });

  qs('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      username: qs('user-username').value.trim(),
      password: qs('user-password').value,
      role: qs('user-role').value,
    };
    if (!payload.username || !payload.password) {
      setStatus(qs('users-status'), 'Username and password required', true);
      return;
    }
    setStatus(qs('users-status'), 'Creating user…');
    try {
      await fetchJson('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      qs('user-form').reset();
      await loadUsers();
    } catch (err) {
      setStatus(qs('users-status'), err.message, true);
    }
  });

  const importBtn = qs('import-jellyfin-btn');
  if (importBtn) {
    importBtn.addEventListener('click', importJellyfinUsers);
  }

  // periodic refresh
  setInterval(() => {
    loadUsers().catch(() => {});
  }, 15000);
});

