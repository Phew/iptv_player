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
const { parseM3U } = require('./src/m3uParser');

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

// Simple proxy to bypass CORS/mixed UA issues for streams
app.get('/api/proxy', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target || !/^https?:\/\//i.test(target)) {
    return res.status(400).json({ error: 'Invalid url' });
  }

  try {
    const targetUrl = new URL(target);
    const referer = `${targetUrl.origin}/`;
    const upstream = await fetch(target, {
      redirect: 'follow',
      headers: {
        'user-agent': 'VLC/3.0.20 LibVLC/3.0.20',
        accept: '*/*',
        referer,
        origin: targetUrl.origin,
        'accept-language': 'en-US,en;q=0.9',
        // Pass through range if present (for TS/MP4 seeking)
        ...(req.headers.range ? { range: req.headers.range } : {}),
      },
    });

    res.status(upstream.status);
    const passHeaders = ['content-type', 'content-length', 'accept-ranges', 'cache-control'];
    passHeaders.forEach((h) => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    const contentType = upstream.headers.get('content-type') || '';
    const isM3U = /mpegurl|vnd\.apple\.mpegurl/i.test(contentType);

    if (!upstream.body) return res.end();

    if (isM3U) {
      // Buffer small manifest, rewrite relative segment URLs to proxied absolute URLs
      const buf = await upstream.text();
      const lines = buf.split(/\r?\n/).map((line) => {
        if (!line || line.startsWith('#')) return line;
        // Absolute URL, leave
        if (/^https?:\/\//i.test(line)) {
          const proxied = `${req.protocol}://${req.get('host')}/api/proxy?url=${encodeURIComponent(line)}`;
          return proxied;
        }
        // Relative -> resolve against targetUrl
        const absolute = new URL(line, targetUrl).toString();
        const proxied = `${req.protocol}://${req.get('host')}/api/proxy?url=${encodeURIComponent(absolute)}`;
        return proxied;
      });
      res.setHeader('content-type', contentType || 'application/vnd.apple.mpegurl');
      res.setHeader('cache-control', 'no-store');
      return res.send(lines.join('\n'));
    }

    pipeline(Readable.fromWeb(upstream.body), res, (err) => {
      if (err) res.destroy(err);
    });
  } catch (err) {
    return res.status(502).json({ error: 'Upstream fetch failed' });
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

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ user: null });
  }
  res.json({ user: req.session.user });
});

app.get('/api/playlists', requireAuth, (_req, res) => {
  const playlists = db.listPlaylists();
  const counts = watcherCounts();
  const total = totalWatchers();
  const withCounts = playlists.map((p) => ({
    ...p,
    viewerCount: total,
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

app.post('/api/playlists/:id/channels/description', requireAdmin, (req, res) => {
  return res.status(410).json({ error: 'Channel notes disabled in favor of EPG.' });
});

// User management (admin only)
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const users = db.listUsers();
  res.json({ users });
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
  if (!req.file) {
    return res.status(400).json({ error: 'Upload an EPG XML file.' });
  }
  try {
    const xml = req.file.buffer.toString('utf8');
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
});

