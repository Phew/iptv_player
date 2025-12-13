# theater.cat

Lightweight, mobile-first IPTV player with login + admin-only playlist uploads. Built with Express, SQLite (better-sqlite3), and a small static UI (vanilla JS + hls.js).

## Quick start

1) Install dependencies  
```bash
npm install
```

2) Configure (optional)  
Copy `sample.env` to `.env` and adjust:
```
PORT=3000
SESSION_SECRET=change-me
ADMIN_USER=admin
ADMIN_PASS=changeme
DB_PATH=./data/theatercat.db
```
The first run seeds an admin user if none exists.

3) Run  
```bash
npm run dev   # with nodemon
# or
npm start
```

## Features
- Login-required experience; sessions stored in SQLite.
- Admin-only `.m3u/.m3u8` uploads (5MB cap) stored in SQLite.
- Simple M3U parser; channels listed with search and quick play.
- HLS playback via `hls.js` when needed; falls back to native video.
- Responsive, modern UI optimized for mobile.

## Notes
- Change the default admin password immediately in `.env` or update the DB.
- Upload parsing is best-effort; ensure playlists contain valid URLs.

