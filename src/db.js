const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'theatercat.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const connection = new Database(dbPath);
connection.pragma('journal_mode = WAL');

connection.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS playlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    uploaded_by INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS epg_programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL DEFAULT 'default',
    tvg_id TEXT NOT NULL,
    title TEXT,
    description TEXT,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (source, tvg_id, start_ts)
  );
  CREATE INDEX IF NOT EXISTS epg_programs_idx ON epg_programs(tvg_id, start_ts);
`);

const createUser = (username, password, role = 'viewer') => {
  const hashed = bcrypt.hashSync(password, 12);
  const stmt = connection.prepare(`
    INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)
  `);
  const info = stmt.run(username, hashed, role);
  return { id: info.lastInsertRowid, username, role };
};

const getUserByUsername = (username) => connection.prepare(`
  SELECT * FROM users WHERE username = ?
`).get(username);

const getUserById = (id) => connection.prepare(`
  SELECT * FROM users WHERE id = ?
`).get(id);

const insertPlaylist = (name, content, uploadedBy) => {
  const stmt = connection.prepare(`
    INSERT INTO playlists (name, content, uploaded_by) VALUES (?, ?, ?)
  `);
  const info = stmt.run(name, content, uploadedBy);
  return info.lastInsertRowid;
};

const listPlaylists = () => connection.prepare(`
  SELECT p.id, p.name, p.created_at, u.username AS uploadedBy
  FROM playlists p
  LEFT JOIN users u ON u.id = p.uploaded_by
  ORDER BY p.created_at DESC
`).all();

const getPlaylistById = (id) => connection.prepare(`
  SELECT p.*, u.username AS uploadedBy
  FROM playlists p
  LEFT JOIN users u ON u.id = p.uploaded_by
  WHERE p.id = ?
`).get(id);

const deletePlaylistById = (id) => connection.prepare(`
  DELETE FROM playlists WHERE id = ?
`).run(id);

const listUsers = () => connection.prepare(`
  SELECT id, username, role, created_at
  FROM users
  ORDER BY created_at DESC
`).all();

const deleteUserById = (id) => connection.prepare(`
  DELETE FROM users WHERE id = ?
`).run(id);

const updateUserPassword = (id, password) => {
  const hashed = bcrypt.hashSync(password, 12);
  return connection.prepare(`
    UPDATE users SET password_hash = ? WHERE id = ?
  `).run(hashed, id);
};

const updateUserRole = (id, role) => connection.prepare(`
  UPDATE users SET role = ? WHERE id = ?
`).run(role, id);

const countAdmins = () => connection.prepare(`
  SELECT COUNT(*) as count FROM users WHERE role = 'admin'
`).get().count;

const replaceEpg = (source, entries = []) => {
  const insert = connection.prepare(`
    INSERT OR REPLACE INTO epg_programs (source, tvg_id, title, description, start_ts, end_ts)
    VALUES (@source, @tvg_id, @title, @description, @start_ts, @end_ts)
  `);
  const tx = connection.transaction((rows) => {
    connection.prepare(`DELETE FROM epg_programs WHERE source = ?`).run(source);
    rows.forEach((row) => insert.run({ source, ...row }));
  });
  tx(entries);
};

const getEpgByTvgIds = (tvgIds = [], nowTs) => {
  if (!tvgIds.length) return {};
  const placeholders = tvgIds.map(() => '?').join(',');
  const stmt = connection.prepare(`
    SELECT tvg_id, title, description, start_ts, end_ts
    FROM epg_programs
    WHERE tvg_id IN (${placeholders})
      AND end_ts >= ?
    ORDER BY start_ts ASC
  `);
  const rows = stmt.all([...tvgIds, nowTs]);
  const map = {};
  rows.forEach((r) => {
    if (!map[r.tvg_id]) map[r.tvg_id] = r;
  });
  return map;
};

const ensureAdminSeed = () => {
  const hasAdmin = connection.prepare(`SELECT 1 FROM users WHERE role = 'admin' LIMIT 1`).get();
  if (hasAdmin) return;

  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS || 'changeme';
  createUser(username, password, 'admin');
  // eslint-disable-next-line no-console
  console.log(`Seeded default admin user "${username}". Change the password ASAP.`);
};

ensureAdminSeed();

module.exports = {
  connection,
  createUser,
  getUserByUsername,
  getUserById,
  insertPlaylist,
  listPlaylists,
  getPlaylistById,
  deletePlaylistById,
  listUsers,
  deleteUserById,
  updateUserPassword,
  updateUserRole,
  countAdmins,
  replaceEpg,
  getEpgByTvgIds,
};

