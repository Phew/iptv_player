const crypto = require('crypto');
const db = require('./db');

const baseUrlRaw = (process.env.JELLYFIN_SERVER_URL || process.env.JELLYFIN_URL || 'https://theater.cat').trim();
const baseUrl = baseUrlRaw.replace(/\/+$/, '');
const apiKey = process.env.JELLYFIN_API_KEY || '';
const timeoutMs = Number.isFinite(Number(process.env.JELLYFIN_TIMEOUT_MS))
  ? Number(process.env.JELLYFIN_TIMEOUT_MS)
  : 8000;
const deviceId = process.env.JELLYFIN_DEVICE_ID
  || crypto.createHash('sha256').update(`tv.theater.cat:${process.env.HOSTNAME || 'local'}`).digest('hex').slice(0, 32);

const isJellyfinConfigured = (requireApiKey = false) => {
  if (!baseUrl) return false;
  if (requireApiKey && !apiKey) return false;
  return true;
};

const ensureConfigured = (requireApiKey = false) => {
  if (!baseUrl) {
    throw new Error('Jellyfin server URL is not configured.');
  }
  if (requireApiKey && !apiKey) {
    throw new Error('Jellyfin API key is not configured on the server.');
  }
};

const buildAuthHeader = () => `MediaBrowser Client="theatercat-iptv", Device="tv.theater.cat", DeviceId="${deviceId}", Version="1.0.0"`;

const buildUrl = (path = '') => {
  const normalized = path.startsWith('/') ? path.slice(1) : path;
  return `${baseUrl}/${normalized}`;
};

const fetchWithTimeout = async (path, options = {}, { requireApiKey = false } = {}) => {
  ensureConfigured(requireApiKey);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const headers = {
    Accept: 'application/json',
    'X-Emby-Authorization': buildAuthHeader(),
    ...(requireApiKey && apiKey ? { 'X-Emby-Token': apiKey } : {}),
    ...(options.headers || {}),
  };
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  try {
    const res = await fetch(buildUrl(path), {
      method: options.method || 'GET',
      headers,
      body: options.body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}));
      const msg = payload?.ErrorMessage || payload?.Message || res.statusText;
      throw new Error(msg || `Jellyfin request failed (${res.status})`);
    }
    return res;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Jellyfin request timed out.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
};

const authenticateJellyfinUser = async ({ username, password }) => {
  if (!username || !password) {
    throw new Error('Username and password are required.');
  }
  const res = await fetchWithTimeout('/Users/AuthenticateByName', {
    method: 'POST',
    body: JSON.stringify({ Username: username, Pw: password }),
  });
  const data = await res.json();
  if (!data?.User) {
    throw new Error('Jellyfin authentication failed.');
  }
  if (data?.User?.Policy?.IsDisabled) {
    throw new Error('Jellyfin account is disabled.');
  }
  const user = data.User;
  const isAdmin = !!user?.Policy?.IsAdministrator;
  return {
    jellyfinUser: user,
    isAdmin,
    accessToken: data.AccessToken || null,
  };
};

const generatePassword = () => crypto.randomBytes(24).toString('hex');

const syncLocalUserFromJellyfin = ({ username, isAdmin }) => {
  const safeUsername = (username || '').trim();
  if (!safeUsername) {
    throw new Error('Jellyfin user is missing a username.');
  }
  const existing = db.getUserByUsername(safeUsername);
  if (existing) {
    if (isAdmin && existing.role !== 'admin') {
      db.updateUserRole(existing.id, 'admin');
      return db.getUserByUsername(safeUsername);
    }
    return existing;
  }
  const pwd = generatePassword();
  return db.createUser(safeUsername, pwd, isAdmin ? 'admin' : 'viewer');
};

const importJellyfinUsers = async () => {
  const res = await fetchWithTimeout('/Users', { method: 'GET' }, { requireApiKey: true });
  const users = await res.json();
  if (!Array.isArray(users)) {
    throw new Error('Unexpected Jellyfin response when listing users.');
  }
  const summary = { created: 0, updated: 0, skipped: 0 };
  users.forEach((u) => {
    const username = (u?.Name || '').trim();
    if (!username) {
      summary.skipped += 1;
      return;
    }
    if (u?.Policy?.IsDisabled) {
      summary.skipped += 1;
      return;
    }
    const isAdmin = !!u?.Policy?.IsAdministrator;
    const existing = db.getUserByUsername(username);
    if (existing) {
      if (isAdmin && existing.role !== 'admin') {
        db.updateUserRole(existing.id, 'admin');
        summary.updated += 1;
      } else {
        summary.skipped += 1;
      }
      return;
    }
    db.createUser(username, generatePassword(), isAdmin ? 'admin' : 'viewer');
    summary.created += 1;
  });
  return summary;
};

module.exports = {
  authenticateJellyfinUser,
  syncLocalUserFromJellyfin,
  importJellyfinUsers,
  isJellyfinConfigured,
};

