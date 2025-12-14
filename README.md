# theater.cat

Lightweight, mobile-first IPTV with auth, admin uploads/imports, EPG ingest, auto-import scheduling, and basic branding. Express + SQLite (better-sqlite3) + vanilla JS + hls.js.

## What it does
- Auth & sessions (SQLite-backed) with admin/viewer roles.
- Admin panels:
  - Upload .m3u/.m3u8 (20MB cap).
  - Import from URL and auto-split by `group-title`; optional wipe before import.
  - Optional scheduled auto-import (default every 12h).
  - Manage users (create/update role/reset password/delete).
  - Upload EPG (file or URL).
  - Branding: set site name from the admin UI.
- Viewer app:
  - Playlist/channel browsing with search, HLS playback (hls.js fallback), live/seek UI.
  - Presence + connection limits; activity/watch stats (admin endpoints).
- Mobile-friendly styling.

## Quick start
1) Install deps  
```bash
npm install
```

2) Configure  
Copy `sample.env` to `.env` and adjust as needed:
```
PORT=3000
SESSION_SECRET=change-me
ADMIN_USER=admin
ADMIN_PASS=changeme
DB_PATH=./data/theatercat.db
SESSION_COOKIE_SECURE=false        # true behind HTTPS/proxy
TRUST_PROXY=0                      # 1+ behind reverse proxy
MAX_CONNECTIONS=4
SITE_NAME=My IPTV                  # optional; also editable in admin UI

# Auto-import (optional)
AUTO_IMPORT_URL=
AUTO_IMPORT_GROUPS=                # comma-separated; empty=all groups
AUTO_IMPORT_PREFIX=
AUTO_IMPORT_HOURS=12
AUTO_IMPORT_CLEAR=false            # true = wipe playlists before import
```
First run seeds an admin user if none exists.

3) Run  
```bash
npm run dev   # nodemon
# or
npm start
```

## Key endpoints / UI
- `/` viewer app (auth required to see playlists)
- `/admin` admin panel (upload/import/EPG/branding)
- `/users` admin user management
- `/api/admin/playlists/import-url` (admin) — import & split by group
- `/api/admin/epg` (admin) — upload XMLTV (file or URL)
- `/api/settings` (public) — site name
- `/api/admin/settings` (admin) — set site name

## Production tips
- Set a strong `SESSION_SECRET` and change `ADMIN_PASS`.
- If behind HTTPS/proxy, set `SESSION_COOKIE_SECURE=true` and `TRUST_PROXY` to your hop count.
- Keep `DB_PATH` on persistent storage; SQLite WAL is enabled.
- If using Cloudflare/NGINX/etc., proxy to your app port and forward `X-Forwarded-Proto`.

## Jellyfin auth & user sync
- Jellyfin server: `https://theater.cat` (defaults to this). IPTV app runs at `tv.theater.cat`; device id defaults to that host.
- Required env: set `JELLYFIN_SERVER_URL=https://theater.cat`; optional `JELLYFIN_DEVICE_ID` and `JELLYFIN_TIMEOUT_MS` (default 8000ms).
- User import requires a Jellyfin admin API key: set `JELLYFIN_API_KEY=<token>` to enable `/api/admin/users/import-jellyfin` (button in Users admin page).
- Sign-in page includes a **Log in with Jellyfin** button; credentials post to the server, sessions stay HttpOnly with same-site cookies (`SESSION_COOKIE_SECURE=true` in prod + `TRUST_PROXY` for your proxy hops).
- Disabled Jellyfin users are skipped; admins stay admins.

## Notes
- Playlists are snapshots; auto-import can re-fetch on a schedule if configured.
- Upload cap: 20MB for playlists. Auto-import cap: 10MB.
- Auto-import replaces playlists of the same name (and can optionally wipe all first).

