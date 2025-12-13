const state = {
  playlists: [],
  stats: { counts: {}, total: 0, limit: 4 },
  users: [],
};

const qs = (id) => document.getElementById(id);
const fmtDate = (value) => new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric' });

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

const ensureAdmin = async () => {
  try {
    const data = await fetchJson('/api/auth/me');
    if (!data.user) throw new Error('Not logged in');
    if (data.user.role !== 'admin') throw new Error('Not admin');
    qs('admin-name').textContent = data.user.username;
    qs('admin-role').textContent = data.user.role;
  } catch (err) {
    console.warn('Admin auth check failed', err?.message || err);
    setStatus(qs('admin-status'), 'Sign in again to access admin.', true);
  }
};

const renderPlaylists = () => {
  const container = qs('admin-playlists');
  container.innerHTML = '';
  if (!state.playlists.length) {
    container.innerHTML = '<p class="muted tiny">No playlists uploaded.</p>';
    return;
  }

  state.playlists.forEach((p) => {
    const row = document.createElement('div');
    row.className = 'playlist';
    row.innerHTML = `
      <div class="name">${p.name}</div>
      <div class="meta">
        <span>${p.uploadedBy || 'unknown'}</span>
        <span>${fmtDate(p.created_at)}</span>
        <span>Viewers: ${p.viewerCount || 0}/${p.viewerLimit || '∞'}</span>
      </div>
      <div class="meta">
        <button class="ghost-btn" data-id="${p.id}">Delete</button>
      </div>
    `;
    row.querySelector('button').addEventListener('click', () => deletePlaylist(p.id));
    container.appendChild(row);
  });
};

const renderStats = () => {
  // stats panel removed in admin UI
};

const loadUsers = async () => {
  try {
    const users = await fetchJson('/api/admin/users');
    state.users = users.users || [];
  } catch (_e) {
    state.users = [];
  }
};

const loadAll = async () => {
  setStatus(qs('admin-status'), 'Loading…');
  try {
    const playlists = await fetchJson('/api/playlists');
    state.playlists = playlists.playlists || [];
    await loadUsers();
    renderPlaylists();
    setStatus(qs('admin-status'), '');
  } catch (err) {
    setStatus(qs('admin-status'), err.message, true);
  }
};

const deletePlaylist = async (id) => {
  if (!window.confirm('Delete this playlist?')) return;
  setStatus(qs('admin-status'), 'Deleting…');
  try {
    await fetchJson(`/api/playlists/${id}`, { method: 'DELETE' });
    await loadAll();
  } catch (err) {
    setStatus(qs('admin-status'), err.message, true);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  ensureAdmin().then(loadAll);
  qs('admin-refresh').addEventListener('click', loadAll);
  qs('admin-logout').addEventListener('click', async () => {
    await fetchJson('/api/auth/logout', { method: 'POST' }).catch(() => {});
    window.location.href = '/';
  });

  const userForm = qs('user-form');
  if (userForm) {
    userForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        username: qs('user-username').value.trim(),
        password: qs('user-password').value,
        role: qs('user-role').value,
      };
      if (!payload.username || !payload.password) {
        setStatus(qs('user-status'), 'Username and password required', true);
        return;
      }
      setStatus(qs('user-status'), 'Creating user…');
      try {
        await fetchJson('/api/admin/users', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        userForm.reset();
        await loadAll();
        setStatus(qs('user-status'), 'User created');
      } catch (err) {
        setStatus(qs('user-status'), err.message, true);
      }
    });
  }

  const uploadForm = qs('admin-upload-form');
  if (uploadForm) {
    uploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(uploadForm);
      setStatus(qs('admin-upload-status'), 'Uploading…');
      try {
        const res = await fetch('/api/playlists', {
          method: 'POST',
          body: form,
          credentials: 'same-origin',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Upload failed');
        setStatus(qs('admin-upload-status'), `Uploaded ${data.name} (${data.channels} channels)`);
        uploadForm.reset();
        await loadData();
      } catch (err) {
        setStatus(qs('admin-upload-status'), err.message, true);
      }
    });
  }

  const epgForm = qs('admin-epg-form');
  if (epgForm) {
    epgForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(epgForm);
      setStatus(qs('admin-epg-status'), 'Uploading EPG…');
      try {
        const res = await fetch('/api/admin/epg', {
          method: 'POST',
          body: form,
          credentials: 'same-origin',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'EPG upload failed');
        setStatus(qs('admin-epg-status'), `EPG loaded (${data.programs} programs)`);
      } catch (err) {
        setStatus(qs('admin-epg-status'), err.message, true);
      }
    });
  }
});

const renderUsers = () => {
  const list = qs('user-list');
  list.innerHTML = '';
  if (!state.users.length) {
    list.innerHTML = '<p class="muted tiny">No users.</p>';
    return;
  }
  state.users.forEach((u) => {
    const row = document.createElement('div');
    row.className = 'playlist';
    row.innerHTML = `
      <div class="name">${u.username}</div>
      <div class="meta">
        <span>${u.role}</span>
        <span>${fmtDate(u.created_at)}</span>
      </div>
      <div class="meta">
        <button class="ghost-btn" data-id="${u.id}">Delete</button>
      </div>
    `;
    row.querySelector('button').addEventListener('click', () => deleteUser(u.id));
    list.appendChild(row);
  });
};

const deleteUser = async (id) => {
  if (!window.confirm('Delete this user?')) return;
  setStatus(qs('user-status'), 'Deleting user…');
  try {
    await fetchJson(`/api/admin/users/${id}`, { method: 'DELETE' });
    await loadData();
    setStatus(qs('user-status'), 'Deleted');
  } catch (err) {
    setStatus(qs('user-status'), err.message, true);
  }
};


