require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const helmet = require('helmet');
const { Readable, pipeline } = require('stream');
const SQLiteStore = require('connect-sqlite3')(session);
const { XMLParser } = require('fast-xml-parser');

const db = require('./src/db');
const { requireAuth, requireAdmin, sanitizeUser, verifyCredentials } = require('./src/auth');
const {
  authenticateJellyfinUser,
  syncLocalUserFromJellyfin,
  importJellyfinUsers,
  isJellyfinConfigured,
} = require('./src/jellyfin');
const { parseM3U } = require('./src/m3uParser');

const buildM3U = (list = []) => {
  const lines = ['#EXTM3U'];
  list.forEach((ch) => {
    const attrs = [
      ch.tvgId ? `tvg-id="${ch.tvgId}"` : '',
      ch.logo ? `tvg-logo="${ch.logo}"` : '',
      ch.group ? `group-title="${ch.group}"` : '',
    ].filter(Boolean).join(' ');
    lines.push(`#EXTINF:-1 ${attrs},${ch.name}`);
    lines.push(ch.url);
  });
  return lines.join('\n');
};

const clearAllPlaylists = () => {
  const existing = db.listPlaylists();
  existing.forEach((p) => db.deletePlaylistById(p.id));
};

const normalizeGroup = (value = '') => {
  const stripped = String(value || '').trim().replace(/^['"]|['"]$/g, '');
  return stripped.toLowerCase();
};

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB cap
});

const PORT = process.env.PORT || 3000;
const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-change-me';
const MAX_CONNECTIONS = Number(process.env.MAX_CONNECTIONS || 4);
const cookieSecure = process.env.SESSION_COOKIE_SECURE === 'true'
  ? true
  : process.env.SESSION_COOKIE_SECURE === 'false'
    ? false
    : 'auto'; // secure when HTTPS, but allow HTTP for local/dev
const dbPath = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data', 'theatercat.db'));
const trustProxy = process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 1;
const AUTO_IMPORT_URL = process.env.AUTO_IMPORT_URL || '';
const AUTO_IMPORT_GROUPS = process.env.AUTO_IMPORT_GROUPS || '';
const AUTO_IMPORT_PREFIX = process.env.AUTO_IMPORT_PREFIX || '';
const AUTO_IMPORT_HOURS = Number(process.env.AUTO_IMPORT_HOURS || 12);
const AUTO_IMPORT_CLEAR = String(process.env.AUTO_IMPORT_CLEAR || '').toLowerCase() === 'true';
const SITE_NAME = process.env.SITE_NAME || db.getSetting('siteName') || 'theater.cat';
const PROXY_TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS) || 20000;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024; // 2MB cap to avoid huge manifests
// Behind HTTPS/load-balancer we need the forwarded proto to set secure cookies
app.set('trust proxy', trustProxy);

app.use(helmet({
  contentSecurityPolicy: false, // keep setup simple for now
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: 'theater.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: true, // honor X-Forwarded-Proto for secure cookies behind proxies
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: cookieSecure,
    maxAge: 1000 * 60 * 60 * 24 * 3, // 3 days
  },
  store: new SQLiteStore({
    db: path.basename(dbPath),
    dir: path.dirname(dbPath),
    concurrentDb: true,
    createDirIfNotExists: true,
  }),
}));

// Track active watchers (in-memory) by session ID
const watchers = new Map(); // sessionID -> { playlistId, updatedAt }
const watcherCounts = () => {
  const counts = {};
  watchers.forEach((entry) => {
    if (!entry.playlistId) return;
    counts[entry.playlistId] = (counts[entry.playlistId] || 0) + 1;
  });
  return counts;
};

const totalWatchers = () => watchers.size;

const cleanupWatchers = () => {
  const now = Date.now();
  const ttlMs = 35_000; // expire after 35s without a ping
  watchers.forEach((entry, key) => {
    if (now - entry.updatedAt > ttlMs) watchers.delete(key);
  });
};
setInterval(cleanupWatchers, 15_000);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'theater.cat' });
});

app.get('/api/settings', (_req, res) => {
  const siteName = db.getSetting('siteName') || SITE_NAME || 'theater.cat';
  res.json({ siteName });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const { siteName } = req.body || {};
  const name = (siteName || '').trim();
  if (!name) return res.status(400).json({ error: 'siteName required' });
  if (name.length > 80) return res.status(400).json({ error: 'siteName too long' });
  db.setSetting('siteName', name);
  return res.json({ ok: true, siteName: name });
});

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';
const hopByHopHeaders = new Set([
  'transfer-encoding',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'upgrade',
]);

const isProbablyManifest = (contentType = '', url = '') => {
  const ct = contentType.toLowerCase();
  return ct.includes('mpegurl') || ct.includes('vnd.apple.mpegurl') || ct.includes('application/x-mpegurl')
    || url.toLowerCase().endsWith('.m3u8') || url.toLowerCase().endsWith('.m3u');
};

const buildProxyUrl = (targetUrl, { referer, origin, agent } = {}) => {
  const params = new URLSearchParams({ url: targetUrl });
  if (referer) params.set('referer', referer);
  if (origin) params.set('origin', origin);
  if (agent) params.set('agent', agent);
  return `/api/proxy?${params.toString()}`;
};

const rewriteManifest = (body, targetUrl, { referer, origin, agent } = {}) => {
  const base = new URL(targetUrl);
  const safeReferer = referer || `${base.origin}/`;
  const safeOrigin = origin || '';
  return body.split(/\r?\n/).map((line) => {
    if (!line || line.startsWith('#')) return line;
    try {
      const absolute = new URL(line, base).toString();
      return buildProxyUrl(absolute, { referer: safeReferer, origin: safeOrigin || undefined, agent });
    } catch (err) {
      return line;
    }
  }).join('\n');
};

const readBodyWithLimit = async (body, maxBytes) => {
  if (!body) return '';
  const reader = body.getReader();
  let size = 0;
  const chunks = [];
  while (true) {
    // eslint-disable-next-line no-await-in-loop
    const { value, done } = await reader.read();
    if (done) break;
    size += value?.length || 0;
    if (size > maxBytes) throw new Error('Manifest too large');
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
};

// Fresh, minimal streaming proxy with manifest rewriting
app.get('/api/proxy', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'url query param required' });

  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid url' });
  }

  const userAgent = req.query.agent || DEFAULT_UA;
  const referer = req.query.referer || `${parsed.origin}/`;
  const originParam = req.query.origin;
  const includeOrigin = Object.prototype.hasOwnProperty.call(req.query, 'origin');
  let origin = null;
  if (originParam === 'omit' || originParam === 'none') {
    origin = null;
  } else if (originParam) {
    origin = originParam;
  } else if (includeOrigin && !originParam) {
    // explicit empty origin should stay null
    origin = null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

  const isManifestLike = isProbablyManifest('', parsed.pathname);
  const headers = {
    'User-Agent': userAgent,
    Accept: '*/*',
    'Accept-Language': req.get('accept-language') || 'en-US,en;q=0.9',
    Referer: referer,
    ...(origin ? { Origin: origin } : {}),
  };

  if (req.headers.range) {
    headers.Range = req.headers.range;
  }

  try {
    const upstream = await fetch(parsed.toString(), {
      method: 'GET',
      headers,
      redirect: 'follow',
      signal: controller.signal,
    });

    const contentType = upstream.headers.get('content-type') || '';
    const statusCode = upstream.status;

    if (isProbablyManifest(contentType, parsed.pathname)) {
      const manifest = await readBodyWithLimit(upstream.body, MAX_MANIFEST_BYTES);
      const rewritten = rewriteManifest(manifest, upstream.url || parsed.toString(), {
        referer,
        origin: includeOrigin ? origin : null,
        agent: req.query.agent,
      });
      res.status(statusCode);
      res.setHeader('Content-Type', contentType || 'application/vnd.apple.mpegurl');
      return res.send(rewritten);
    }

    res.status(statusCode);
    upstream.headers.forEach((value, key) => {
      if (!hopByHopHeaders.has(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    });

    return pipeline(
      Readable.fromWeb(upstream.body),
      res,
      (err) => {
        if (err && !res.headersSent) {
          res.status(502).end();
        }
      },
    );
  } catch (err) {
    const msg = err.name === 'AbortError' ? 'Upstream timed out' : err.message || 'Proxy failed';
    return res.status(502).json({ error: msg });
  } finally {
    clearTimeout(timer);
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const user = verifyCredentials(username, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  req.session.user = sanitizeUser(user);
  req.session.save(() => {
    res.json({ user: sanitizeUser(user) });
  });
});

app.post('/api/auth/login/jellyfin', async (req, res) => {
  if (!isJellyfinConfigured()) {
    return res.status(503).json({ error: 'Jellyfin login is not configured on this server.' });
  }
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  try {
    const result = await authenticateJellyfinUser({ username, password });
    const localUser = syncLocalUserFromJellyfin({
      username: result?.jellyfinUser?.Name || username,
      isAdmin: result?.isAdmin,
    });
    const safeUser = sanitizeUser(localUser);
    req.session.user = safeUser;
    req.session.save(() => res.json({ user: safeUser }));
  } catch (err) {
    const msg = err?.message || 'Jellyfin login failed.';
    res.status(401).json({ error: msg });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  const user = req.session?.user ? sanitizeUser(req.session.user) : null;
  return res.status(200).json({ user });
});

app.get('/api/playlists', requireAuth, (_req, res) => {
  const playlists = db.listPlaylists();
  const counts = watcherCounts();
  const withCounts = playlists.map((p) => ({
    ...p,
    viewerCount: counts[p.id] || 0,
    viewerLimit: MAX_CONNECTIONS,
  }));
  res.json({ playlists: withCounts });
});

app.get('/api/playlists/:id/channels', requireAuth, (req, res) => {
  const playlistId = Number(req.params.id);
  const playlist = db.getPlaylistById(playlistId);
  if (!playlist) {
    return res.status(404).json({ error: 'Playlist not found.' });
  }

  const channels = parseM3U(playlist.content);
  const tvgIds = channels.map((c) => c.tvgId).filter(Boolean);
  const epgMap = db.getEpgByTvgIds(tvgIds, Date.now());
  const enriched = channels.map((c) => {
    const epg = c.tvgId ? epgMap[c.tvgId] : null;
    return {
      ...c,
      programTitle: epg?.title || '',
      programDesc: epg?.description || '',
      userAgent: c.userAgent,
      referer: c.referer,
    };
  });
  res.json({
    playlist: {
      id: playlist.id,
      name: playlist.name,
      uploadedBy: playlist.uploadedBy,
      createdAt: playlist.created_at,
    },
    channels: enriched,
  });
});

app.delete('/api/playlists/:id', requireAdmin, (req, res) => {
  const playlistId = Number(req.params.id);
  const playlist = db.getPlaylistById(playlistId);
  if (!playlist) {
    return res.status(404).json({ error: 'Playlist not found.' });
  }
  db.deletePlaylistById(playlistId);
  return res.json({ ok: true });
});

app.post('/api/playlists', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Upload a .m3u or .m3u8 file.' });
  }

  const friendlyName = req.body.name?.trim() || req.file.originalname.replace(/\.[^.]+$/, '');
  const content = req.file.buffer.toString('utf8');
  const channels = parseM3U(content);

  if (!channels.length) {
    return res.status(400).json({ error: 'No channels found in playlist.' });
  }

  const id = db.insertPlaylist(friendlyName, content, req.session.user.id);
  res.status(201).json({ id, name: friendlyName, channels: channels.length });
});

// Import playlist from remote URL and auto-split by group-title
app.post('/api/admin/playlists/import-url', requireAdmin, async (req, res) => {
  const { url, groups, namePrefix } = req.body || {};
  try {
    const created = await importFromUrlAndSplit({
      url,
      groups,
      namePrefix,
      uploadedBy: req.session.user.id,
    });
    return res.json({ ok: true, imported: created.length, playlists: created });
  } catch (err) {
    const msg = err?.message || 'Import failed';
    const isSize = msg.toLowerCase().includes('too large');
    return res.status(isSize ? 413 : 400).json({ error: msg });
  }
});

const importFromUrlAndSplit = async ({ url, groups, namePrefix, uploadedBy = null, maxBytes = 10 * 1024 * 1024 }) => {
  if (!url || !/^https?:\/\//i.test(url)) {
    throw new Error('A valid http/https URL is required.');
  }

  let content = '';
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const upstream = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!upstream.ok) {
      throw new Error(`Failed to fetch URL (${upstream.status})`);
    }
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > maxBytes) {
      throw new Error('Playlist too large (max 10MB).');
    }
    content = buf.toString('utf8');
  } catch (err) {
    throw new Error(`Failed to fetch URL: ${err.message}`);
  }

  const channels = parseM3U(content);
  if (!channels.length) {
    throw new Error('No channels found in playlist.');
  }

  const requestedGroups = Array.isArray(groups)
    ? groups
    : (typeof groups === 'string'
      ? groups.split(',').map((g) => g.trim()).filter(Boolean)
      : []);
  const requestedGroupsNorm = requestedGroups.map((g) => normalizeGroup(g)).filter(Boolean);

  const groupMap = new Map();
  channels.forEach((ch) => {
    const displayName = ch.group || 'Ungrouped';
    const norm = normalizeGroup(displayName) || 'ungrouped';
    if (!groupMap.has(norm)) groupMap.set(norm, { name: displayName, items: [] });
    groupMap.get(norm).items.push(ch);
  });

  const targetGroups = requestedGroupsNorm.length
    ? requestedGroupsNorm
    : Array.from(groupMap.keys());

  const created = [];
  const prefix = (namePrefix || '').trim();

  const existing = db.listPlaylists(); // {id,name}

  targetGroups.forEach((g) => {
    let bucket = groupMap.get(g);
    if (!bucket) {
      // Fallback: partial match on normalized key or display name
      for (const [key, val] of groupMap.entries()) {
        const nameLc = (val.name || '').toLowerCase();
        if (key.includes(g) || nameLc.includes(g)) {
          bucket = val;
          break;
        }
      }
    }
    if (!bucket || !bucket.items.length) return;
    const playlistName = `${prefix ? `${prefix} · ` : ''}${bucket.name}`;
    const m3uText = buildM3U(bucket.items);

    // Delete any playlist with the same name to avoid duplicates
    const dup = existing.find((p) => p.name === playlistName);
    if (dup) {
      db.deletePlaylistById(dup.id);
    }

    const id = db.insertPlaylist(playlistName, m3uText, uploadedBy);
    created.push({ id, name: playlistName, channels: bucket.items.length });
  });

  if (!created.length) {
    throw new Error('No matching groups found to import.');
  }

  return created;
};

const scheduleAutoImport = () => {
  if (!AUTO_IMPORT_URL) return;
  const hours = Number.isFinite(AUTO_IMPORT_HOURS) && AUTO_IMPORT_HOURS > 0 ? AUTO_IMPORT_HOURS : 12;
  const ms = hours * 60 * 60 * 1000;
  const run = async () => {
    try {
      if (AUTO_IMPORT_CLEAR) {
        clearAllPlaylists();
        // eslint-disable-next-line no-console
        console.log('[auto-import] Cleared all existing playlists before import');
      }
      const created = await importFromUrlAndSplit({
        url: AUTO_IMPORT_URL,
        groups: AUTO_IMPORT_GROUPS,
        namePrefix: AUTO_IMPORT_PREFIX,
        uploadedBy: null,
      });
      // eslint-disable-next-line no-console
      console.log(`[auto-import] Imported ${created.length} playlist(s) from URL`);
      // Persist site name env override if provided
      if (process.env.SITE_NAME) db.setSetting('siteName', process.env.SITE_NAME);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[auto-import] Failed:', err.message);
    }
  };
  run();
  setInterval(run, ms).unref();
};

app.post('/api/playlists/:id/channels/description', requireAdmin, (req, res) => {
  return res.status(410).json({ error: 'Channel notes disabled in favor of EPG.' });
});

// User management (admin only)
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const users = db.listUsers();
  res.json({ users });
});

app.post('/api/admin/users/import-jellyfin', requireAdmin, async (_req, res) => {
  if (!isJellyfinConfigured(true)) {
    return res.status(503).json({ error: 'Jellyfin import is not configured (missing API key).' });
  }
  try {
    const summary = await importJellyfinUsers();
    return res.json({ ok: true, ...summary });
  } catch (err) {
    const msg = err?.message || 'Failed to import Jellyfin users';
    return res.status(400).json({ error: msg });
  }
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'username, password, role required' });
  }
  if (!['admin', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'role must be admin or viewer' });
  }
  if (db.getUserByUsername(username)) {
    return res.status(409).json({ error: 'User already exists' });
  }
  const user = db.createUser(username, password, role);
  res.status(201).json({ user });
});

app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { password, role } = req.body || {};
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (role && !['admin', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'role must be admin or viewer' });
  }

  if (role) db.updateUserRole(id, role);
  if (password) db.updateUserPassword(id, password);
  const updated = db.getUserById(id);
  res.json({ user: sanitizeUser(updated) });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.id === req.session.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  if (user.role === 'admin' && db.countAdmins() <= 1) {
    return res.status(400).json({ error: 'Cannot delete the last admin' });
  }

  db.deleteUserById(id);
  res.json({ ok: true });
});

app.post('/api/watch/ping', requireAuth, (req, res) => {
  cleanupWatchers();
  const sessionId = req.sessionID;
  const playlistId = Number(req.body?.playlistId);
  const channelName = req.body?.channelName || '';
  if (!playlistId) return res.status(400).json({ error: 'playlistId required' });

  const current = watchers.get(sessionId);
  const totalCount = totalWatchers();
  const alreadyWatching = current && current.playlistId === playlistId;

  if (!alreadyWatching && totalCount >= MAX_CONNECTIONS) {
    return res.status(429).json({ error: 'Max connections reached', limit: MAX_CONNECTIONS, count: totalCount });
  }

  watchers.set(sessionId, {
    playlistId,
    channelName,
    updatedAt: Date.now(),
    user: req.session.user?.username || 'guest',
    page: 'watch',
  });
  const updatedCounts = watcherCounts();
  res.json({ ok: true, count: totalWatchers(), limit: MAX_CONNECTIONS, perPlaylist: updatedCounts });
});

app.post('/api/watch/stop', requireAuth, (req, res) => {
  watchers.delete(req.sessionID);
  res.json({ ok: true });
});

app.get('/api/watch/stats', requireAuth, (_req, res) => {
  cleanupWatchers();
  const sessions = [];
  watchers.forEach((entry, key) => {
    sessions.push({
      sessionId: key,
      user: entry.user || 'guest',
      playlistId: entry.playlistId,
      channelName: entry.channelName || '',
      page: entry.page || 'watch',
      updatedAt: entry.updatedAt,
    });
  });
  res.json({ counts: watcherCounts(), total: totalWatchers(), limit: MAX_CONNECTIONS, sessions });
});

// Activity ping for presence
app.post('/api/activity', requireAuth, (req, res) => {
  const sessionId = req.sessionID;
  const page = req.body?.page || 'home';
  const entry = watchers.get(sessionId) || {};
  watchers.set(sessionId, {
    ...entry,
    page,
    updatedAt: Date.now(),
    user: req.session.user?.username || 'guest',
  });
  res.json({ ok: true });
});

app.get('/api/activity/list', requireAdmin, (_req, res) => {
  cleanupWatchers();
  const sessions = [];
  watchers.forEach((entry, key) => {
    sessions.push({
      sessionId: key,
      user: entry.user || 'guest',
      page: entry.page || 'watch',
      playlistId: entry.playlistId,
      channelName: entry.channelName || '',
      updatedAt: entry.updatedAt,
    });
  });
  res.json({ sessions });
});

// Admin EPG upload (XMLTV)
app.post('/api/admin/epg', requireAdmin, upload.single('file'), async (req, res) => {
  // Accept either file upload or url (NOT both at once)
  let xml = '';
  if (req.file) {
    xml = req.file.buffer.toString('utf8');
  } else if (req.body.url) {
    try {
      const response = await fetch(req.body.url, { timeout: 15000 });
      if (!response.ok) throw new Error(`Failed to fetch URL: ${response.statusText}`);
      xml = await response.text();
    } catch (err) {
      return res.status(400).json({ error: `Failed to fetch remote EPG: ${err.message}` });
    }
  } else {
    return res.status(400).json({ error: 'Upload a file or provide a URL.' });
  }

  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '',
      parseAttributeValue: true,
      parseTagValue: true,
      trimValues: true,
    });
    const parsed = parser.parse(xml);
    const programs = parsed?.tv?.programme || [];
    const entries = programs.map((p) => {
      const start = p.start ? Date.parse(p.start) : 0;
      const stop = p.stop ? Date.parse(p.stop) : 0;
      return {
        tvg_id: p.channel || '',
        title: Array.isArray(p.title) ? p.title[0] : p.title || '',
        description: Array.isArray(p.desc) ? p.desc[0] : p.desc || '',
        start_ts: Number.isFinite(start) ? start : 0,
        end_ts: Number.isFinite(stop) ? stop : start + 30 * 60 * 1000,
      };
    }).filter((e) => e.tvg_id && e.start_ts && e.end_ts);
    db.replaceEpg('default', entries);
    res.json({ ok: true, programs: entries.length });
  } catch (err) {
    res.status(400).json({ error: 'Failed to parse EPG XML.' });
  }
});

// Centralized error handler for multer and other errors
// Keep JSON errors so the frontend can show meaningful messages.
// Must be after routes.
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const map = {
      LIMIT_FILE_SIZE: 'Upload too large. Max 20MB.',
      LIMIT_UNEXPECTED_FILE: 'Unexpected file upload.',
    };
    const msg = map[err.code] || 'Upload failed.';
    return res.status(400).json({ error: msg });
  }
  // Fallback
  console.error('Unhandled error:', err); // keep minimal logging
  return res.status(500).json({ error: 'Server error.' });
});

// Serve static UI
app.use(express.static(path.join(__dirname, 'public')));
const ensureAdminPage = (req, res, next) => {
  if (!req.session?.user) return res.redirect('/');
  if (req.session.user.role !== 'admin') return res.redirect('/');
  return next();
};

app.get('/admin', ensureAdminPage, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/users', ensureAdminPage, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-users.html'));
});
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`theater.cat running on http://localhost:${PORT}`);
  scheduleAutoImport();
});

