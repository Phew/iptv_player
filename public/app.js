const state = {
  user: null,
  playlists: [],
  channels: [],
  selectedPlaylistId: null,
  currentChannel: null,
  hls: null,
  watchTimer: null,
  viewerTotal: 0,
  isLive: true,
  siteName: 'theater.cat',
};

const els = {};

const qs = (id) => document.getElementById(id);
const DEBUG_LOGGING = true;
const dlog = (...args) => {
  if (!DEBUG_LOGGING) return;
  try { console.log('[iptv]', ...args); } catch (_e) {}
};
const fmtDate = (value) => new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric' });
const proxyUrl = (url) => `/api/proxy?url=${encodeURIComponent(url)}`;
const rewriteUrl = (url) => {
  if (!url) return url;
  if (url.startsWith('/api/proxy?') || url.includes('/api/proxy?url=')) return url;
  return proxyUrl(url);
};

const buildCandidates = (url) => {
  const clean = (url || '').trim();
  if (!clean) return [];
  const variants = [clean];
  const noExt = !/\.[a-z0-9]+(\?|$)/i.test(clean);
  if (noExt) {
    variants.push(`${clean}.m3u8`);
    variants.push(`${clean}/index.m3u8`);
  }

  const list = [];
  variants.forEach((v) => {
    try {
      const parsed = new URL(v.replace(/^\s+/, ''));
      const isHttp = parsed.protocol === 'http:';
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname || '');
      const upgraded = isHttp ? v.replace(/^http:/i, 'https:') : v;

      // If host is IP or original is http, force proxy (avoid mixed content/cert issues)
      if (isHttp || isIp) {
        list.push({ url: upgraded, proxy: true });
        if (upgraded !== v) list.push({ url: v, proxy: true });
        return;
      }

      // HTTPS host: prefer proxied first (avoids mixed content / bad certs), then direct fallback
      list.push({ url: upgraded, proxy: true });
      list.push({ url: upgraded, proxy: false });
    } catch (_e) {
      // Fallback: keep original proxied
      list.push({ url: v, proxy: true });
    }
  });

  return list.filter((c, idx, arr) =>
    arr.findIndex((x) => x.url === c.url && x.proxy === c.proxy) === idx
  );
};

const tryPlay = async (video) => {
  try {
    await video.play();
    return true;
  } catch (err) {
    setStatus(qs('player-status'), `Autoplay blocked or error: ${err.message}`, true);
    return false;
  }
};

const setStatus = (el, message, isError = false) => {
  if (!el) return;
  el.textContent = message || '';
  el.style.color = isError ? '#ff9fbf' : 'var(--accent)';
};

const toggle = (el, show) => {
  if (!el) return;
  el.classList[show ? 'remove' : 'add']('hidden');
};

let stopWatchInFlight = false;
const stopWatch = async () => {
  if (state.watchTimer) {
    clearInterval(state.watchTimer);
    state.watchTimer = null;
  }
  if (stopWatchInFlight) return;
  stopWatchInFlight = true;
  dlog('watch: stop');
  await fetchJson('/api/watch/stop', { method: 'POST' }).catch(() => {});
  stopWatchInFlight = false;
};

const startWatch = (playlistId, channelName = '') => {
  if (!playlistId) return;
  stopWatch();
  dlog('watch: start', { playlistId, channelName });
  const send = async () => {
    try {
      const data = await fetchJson('/api/watch/ping', {
        method: 'POST',
        body: JSON.stringify({ playlistId, channelName }),
      });
      setStatus(qs('player-status'), `Viewers: ${data.count}/${data.limit}`);
      state.viewerTotal = data.count || 0;
      updateViewerBadge();
    } catch (err) {
      setStatus(qs('player-status'), err.message, true);
      if (String(err.message || '').toLowerCase().includes('max connections')) {
        stopWatch();
      }
    }
  };
  send();
  state.watchTimer = setInterval(send, 15000);
};

const fetchJson = async (url, options = {}) => {
  const method = options.method || 'GET';
  dlog('fetchJson: request', { url, method });
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  dlog('fetchJson: response', { url, method, status: res.status, ok: res.ok });
  if (!res.ok) {
    const error = data.error || 'Request failed';
    throw new Error(error);
  }
  return data;
};

const handleLoginSuccess = (user) => {
  state.user = user;
  dlog('auth: login success', { user });
  if (state.user) sessionStorage.setItem('user', JSON.stringify(state.user));
  updateUserUI();
  setStatus(qs('auth-status'), '');
  loadPlaylists();
};

const updateUserUI = () => {
  const user = state.user;
  qs('user-name').textContent = user ? user.username : 'Guest';
  toggle(qs('logout-btn'), !!user);
  toggle(qs('auth-card'), !user);
  toggle(qs('app-card'), !!user);
  const onAdmin = window.location.pathname.startsWith('/admin');
  const onUsers = window.location.pathname.startsWith('/users');
  toggle(qs('admin-link'), user?.role === 'admin' && !onAdmin);
  toggle(qs('users-link'), user?.role === 'admin' && !onUsers);
};

const applySiteName = (name) => {
  if (!name) return;
  state.siteName = name;
  const titleEl = qs('site-title');
  if (titleEl) titleEl.textContent = name;
  document.title = `${name} · IPTV`;
};

const updateViewerBadge = () => {
  const label = qs('viewer-count-text');
  if (label) label.textContent = `${state.viewerTotal || 0} active`;
};

const loadViewerStats = async () => {
  try {
    const stats = await fetchJson('/api/watch/stats');
    state.viewerTotal = stats.total || 0;
    updateViewerBadge();
  } catch (_err) {
    // ignore
  }
};

const renderPlaylists = () => {
  const container = qs('playlist-list');
  container.innerHTML = '';
  if (!state.playlists.length) {
    container.innerHTML = '<p class="muted tiny">No playlists yet.</p>';
    return;
  }

  state.playlists.forEach((p) => {
    const div = document.createElement('div');
    div.className = `playlist ${state.selectedPlaylistId === p.id ? 'active' : ''}`;
    div.innerHTML = `
      <div class="name">${p.name}</div>
      <div class="meta">
        <span>${p.uploadedBy || 'unknown'}</span>
        <span>${fmtDate(p.created_at)}</span>
      </div>
    `;
    div.addEventListener('click', () => selectPlaylist(p.id));
    container.appendChild(div);
  });
};

const renderChannels = (filter = '') => {
  const grid = qs('channels-grid');
  grid.innerHTML = '';
  const term = filter.toLowerCase();
  const filtered = state.channels.filter((c) =>
    c.name.toLowerCase().includes(term) ||
    (c.group && c.group.toLowerCase().includes(term)) ||
    (c.programTitle && c.programTitle.toLowerCase().includes(term)) ||
    (c.programDesc && c.programDesc.toLowerCase().includes(term))
  );

  if (!filtered.length) {
    grid.innerHTML = '<p class="muted tiny">No channels found.</p>';
    return;
  }

  filtered.forEach((ch) => {
    const card = document.createElement('div');
    card.className = `channel ${state.currentChannel?.name === ch.name ? 'active' : ''}`;
    card.innerHTML = `
      <div class="name">${ch.name}</div>
      <div class="tag">
        <span class="dot"></span>
        <span>${ch.group || 'Ungrouped'}</span>
      </div>
      ${ch.programTitle ? `<p class="muted tiny">${ch.programTitle}</p>` : ''}
      ${ch.programDesc ? `<p class="muted tiny">${ch.programDesc}</p>` : ''}
    `;
    card.addEventListener('click', () => playChannel(ch));
    grid.appendChild(card);
  });
};

const selectPlaylist = async (id) => {
  if (!id) return;
  state.selectedPlaylistId = id;
  dlog('playlist: select', { id });
  renderPlaylists();
  setStatus(qs('auth-status'), 'Loading channels…');
  try {
    const data = await fetchJson(`/api/playlists/${id}/channels`);
    state.channels = data.channels || [];
    qs('channels-title').textContent = `${data.playlist.name} · ${state.channels.length} channels`;
    renderChannels(qs('channel-search').value);
    setStatus(qs('auth-status'), '');
  } catch (err) {
    setStatus(qs('auth-status'), err.message, true);
  }
};

const destroyPlayer = () => {
  const video = qs('video');
  dlog('player: destroy');
  video.onerror = null;
  stopWatch();
  if (state.hls) {
    state.hls.destroy();
    state.hls = null;
  }
  video.pause();
  video.src = '';
};

const playChannel = (channel) => {
  const video = qs('video');
  destroyPlayer();
  dlog('player: playChannel invoked', { channel });

  setStatus(qs('player-status'), 'Loading stream…');

  video.onerror = () => {
    setStatus(qs('player-status'), 'Playback failed (see console for details).', true);
  };

  const statusEl = qs('player-status');
  const candidates = buildCandidates(channel.url);
  dlog('player: candidates', candidates);
  let attempt = 0;
  let attemptTimer = null;
  let bufferingTimer = null;

  const clearBufferingTimer = () => {
    if (bufferingTimer) {
      clearTimeout(bufferingTimer);
      bufferingTimer = null;
    }
  };

  const clearAttemptTimer = () => {
    if (attemptTimer) {
      clearTimeout(attemptTimer);
      attemptTimer = null;
    }
  };

  const markBuffering = (message = 'Buffering…') => {
    clearBufferingTimer();
    setStatus(statusEl, message);
    bufferingTimer = setTimeout(() => {
      startNext('Buffering timeout, trying next source…');
    }, 15000);
  };

  const startNext = (reason) => {
    clearAttemptTimer();
    clearBufferingTimer();
    if (reason) setStatus(statusEl, reason, true);
    if (reason) dlog('player: startNext', { reason, attempt, total: candidates.length });
    attempt += 1;
    if (attempt >= candidates.length) {
      setStatus(statusEl, 'All sources failed.', true);
      return;
    }
    startAttempt();
  };

  const startAttempt = () => {
    clearAttemptTimer();
    clearBufferingTimer();
    destroyPlayer();
    let failedThisAttempt = false;
    const candidate = candidates[attempt];
    const source = candidate.url;
    const proxied = candidate.proxy ? rewriteUrl(source) : source;
    const isHls = source.toLowerCase().includes('.m3u8');
    const useHls = !!(window.Hls && window.Hls.isSupported());
    dlog('player: startAttempt', {
      attempt: attempt + 1,
      total: candidates.length,
      source,
      proxied: candidate.proxy,
      usingHlsJs: isHls && useHls,
    });
    const maxNetworkRecoveries = 2;
    const maxMediaRecoveries = 2;
    let networkRecoveries = 0;
    let mediaRecoveries = 0;

    setStatus(statusEl, `Loading source ${attempt + 1}/${candidates.length}…`);
    clearAttemptTimer();
    attemptTimer = setTimeout(() => {
      startNext('Timeout, trying next source…');
    }, 15000);

    video.oncanplay = () => {
      setStatus(statusEl, '');
      clearAttemptTimer();
      video.play().catch((err) => {
        setStatus(statusEl, `Playback error: ${err.message}`, true);
        dlog('player: video.play error', err?.message);
      });
      video.oncanplay = null;
    };

    video.onplaying = () => {
      clearAttemptTimer();
      clearBufferingTimer();
      setStatus(statusEl, '');
    };
    video.ontimeupdate = () => updateProgress(video);
    video.onloadedmetadata = () => updateProgress(video);
    video.onwaiting = () => {
      if (state.hls) state.hls.startLoad();
      markBuffering();
    };
    video.onstalled = () => {
      if (state.hls) state.hls.startLoad();
      markBuffering();
    };

    if (isHls && useHls) {
      class ProxyLoader extends Hls.DefaultConfig.loader {
        load(context, config, callbacks) {
          const updated = { ...context, url: rewriteUrl(context.url) };
          super.load(updated, config, callbacks);
        }
      }
      // Use proxy loader only when candidate is marked proxied to avoid mixed-content/cert issues.
      // Allow direct loader for safe HTTPS hosts that shouldn't be proxied (some reject proxy UA/headers).
      const loaderClass = candidate.proxy ? ProxyLoader : Hls.DefaultConfig.loader;
      const hlsConfig = {
        ...Hls.DefaultConfig,
        loader: loaderClass,
        maxBufferLength: 12,
        maxMaxBufferLength: 30,
        liveSyncDurationCount: 3,
        fragLoadingMaxRetry: 1,
        manifestLoadingMaxRetry: 1,
        lowLatencyMode: false,
        startLevel: -1,
      };
      state.hls = new Hls(hlsConfig);
      state.hls.attachMedia(video);
      state.hls.on(Hls.Events.MEDIA_ATTACHED, () => {
        state.hls.loadSource(proxied);
        dlog('hls: media attached, loading source', proxied);
      });
      state.hls.on(Hls.Events.LEVEL_LOADED, () => {
        clearAttemptTimer();
        video.play().catch(() => {});
        dlog('hls: level loaded');
      });
      state.hls.on(Hls.Events.ERROR, (_event, data) => {
        if (!data) return;
        if (failedThisAttempt) return;
        const code = data?.response?.code ? ` (HTTP ${data.response.code})` : '';
        const codeNum = data?.response?.code || 0;
        dlog('hls: error', { type: data.type, details: data.details, code: codeNum, fatal: data.fatal });

        // Treat common dead-source codes as immediate failures (even if non-fatal)
        if ([404, 403, 410, 429].includes(codeNum)) {
          const msg = codeNum === 429
            ? 'Proxy rate limited (429). Trying next source…'
            : `Source returned ${codeNum}. Trying next source…`;
          failedThisAttempt = true;
          startNext(msg);
          return;
        }

        if (data.details === 'manifestParsingError') {
          failedThisAttempt = true;
          startNext('Manifest could not be parsed. Trying next source…');
          return;
        }
        if (data.fatal) {
          if (data.type === Hls.ErrorTypes.NETWORK_ERROR && networkRecoveries < maxNetworkRecoveries) {
            networkRecoveries += 1;
            markBuffering(`Network hiccup… retry ${networkRecoveries}/${maxNetworkRecoveries}`);
            state.hls.startLoad();
            return;
          }
          if (data.type === Hls.ErrorTypes.MEDIA_ERROR && mediaRecoveries < maxMediaRecoveries) {
            mediaRecoveries += 1;
            markBuffering(`Recovering stream… ${mediaRecoveries}/${maxMediaRecoveries}`);
            state.hls.recoverMediaError();
            return;
          }
          startNext(`HLS fatal (${data.type || 'unknown'}${code}). Trying next source…`);
        } else if (data.details) {
          const bufferingDetails = ['bufferStalledError', 'fragLoadError', 'fragLoadTimeout'];
          if (bufferingDetails.includes(data.details)) {
            markBuffering('Buffering… retrying…');
            state.hls.startLoad();
            return;
          }
          if (data.details === 'manifestLoadError' || data.details === 'levelLoadError') {
            failedThisAttempt = true;
            startNext('Manifest/level load failed. Trying next source…');
            return;
          }
          setStatus(statusEl, `HLS issue: ${data.details}${code}`, true);
        }
      });
      state.hls.on(Hls.Events.BUFFER_STALLED, () => {
        markBuffering('Buffering… retrying…');
        state.hls.startLoad();
    dlog('hls: buffer stalled');
      });
    } else {
      video.src = proxied;
      video.onerror = () => {
        startNext('Playback failed. Trying next source…');
    dlog('player: video tag error, trying next source');
      };
      video.load();
      video.play().catch(() => {});
    }

    // detect live (no duration or Infinity)
    setTimeout(() => {
      const live = !Number.isFinite(video.duration) || video.duration === 0;
      state.isLive = live;
      toggle(qs('live-pill'), live);
      toggle(qs('seek-slider'), !live);
      toggle(qs('time-total'), !live);
    }, 500);
  };

  if (!candidates.length) {
    setStatus(statusEl, 'No valid URL for this channel.', true);
    return;
  }
  startAttempt();

  state.currentChannel = channel;
  renderChannels(qs('channel-search').value);
  qs('now-title').textContent = channel.name;
  qs('now-meta').textContent = channel.group || 'Live channel';
  qs('now-pill').textContent = 'Playing';
  if (state.selectedPlaylistId) {
    startWatch(state.selectedPlaylistId, channel.name);
  }
};

const formatTime = (sec) => {
  if (!Number.isFinite(sec)) return '00:00';
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

const updateProgress = (video) => {
  const current = qs('time-current');
  const total = qs('time-total');
  const seek = qs('seek-slider');
  if (!video || !seek) return;

  if (!Number.isFinite(video.duration) || video.duration === 0) {
    current.textContent = formatTime(video.currentTime);
    total.textContent = '';
    seek.value = 0;
    return;
  }
  current.textContent = formatTime(video.currentTime);
  total.textContent = formatTime(video.duration);
  seek.value = (video.currentTime / video.duration) * 100 || 0;
};

const bindPlayerControls = () => {
  const video = qs('video');
  const playBtn = qs('play-btn');
  const playToggle = qs('play-toggle');
  const muteBtn = qs('mute-btn');
  const vol = qs('volume-slider');
  const seek = qs('seek-slider');
  const fsBtn = qs('fs-btn');
  const pipBtn = qs('pip-btn');

  const setPlayingState = (playing) => {
    if (playBtn) playBtn.textContent = playing ? '❚❚' : '▶';
    if (playToggle) playToggle.textContent = playing ? '❚❚' : '▶';
  };

  playBtn?.addEventListener('click', () => {
    if (video.paused) video.play(); else video.pause();
  });
  playToggle?.addEventListener('click', () => {
    if (video.paused) video.play(); else video.pause();
  });
  video.addEventListener('play', () => setPlayingState(true));
  video.addEventListener('pause', () => setPlayingState(false));

  muteBtn?.addEventListener('click', () => {
    video.muted = !video.muted;
    muteBtn.textContent = video.muted ? '🔇' : '🔈';
  });
  vol?.addEventListener('input', (e) => {
    video.muted = false;
    video.volume = parseFloat(e.target.value);
    if (muteBtn) muteBtn.textContent = '🔈';
  });

  seek?.addEventListener('input', (e) => {
    if (!Number.isFinite(video.duration) || video.duration === 0) return;
    const pct = parseFloat(e.target.value);
    video.currentTime = (pct / 100) * video.duration;
  });

  fsBtn?.addEventListener('click', () => {
    const wrap = qs('player-frame') || video;
    if (!document.fullscreenElement) {
      wrap.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  });

  pipBtn?.addEventListener('click', async () => {
    if (document.pictureInPictureElement) {
      await document.exitPictureInPicture().catch(() => {});
    } else if (video.requestPictureInPicture) {
      await video.requestPictureInPicture().catch(() => {});
    }
  });
};

const loadPlaylists = async () => {
  try {
    const data = await fetchJson('/api/playlists');
    state.playlists = data.playlists || [];
    await loadViewerStats();
    renderPlaylists();
  } catch (err) {
    setStatus(qs('auth-status'), err.message, true);
  }
};

const refreshSession = async () => {
  try {
    const settings = await fetchJson('/api/settings');
    if (settings?.siteName) applySiteName(settings.siteName);
  } catch (_e) {
    // ignore
  }
  // optimistic: use cached user to avoid flash logout on refresh
  const cached = sessionStorage.getItem('user');
  if (cached && !state.user) {
    try {
      state.user = JSON.parse(cached);
      updateUserUI();
    } catch (_e) {
      // ignore
    }
  }
  try {
    const data = await fetchJson('/api/auth/me');
    state.user = data.user;
    if (state.user) sessionStorage.setItem('user', JSON.stringify(state.user));
  } catch (err) {
    state.user = null;
    sessionStorage.removeItem('user');
  }
  updateUserUI();
  if (state.user) {
    loadPlaylists();
  }
};

const loginWithJellyfin = async () => {
  const username = qs('username').value.trim();
  const password = qs('password').value;
  if (!username || !password) {
    setStatus(qs('auth-status'), 'Username and password required for Jellyfin login.', true);
    return;
  }
  setStatus(qs('auth-status'), 'Signing in with Jellyfin…');
  try {
    const data = await fetchJson('/api/auth/login/jellyfin', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    handleLoginSuccess(data.user);
  } catch (err) {
    setStatus(qs('auth-status'), err.message, true);
  }
};

const bindAuth = () => {
  qs('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setStatus(qs('auth-status'), 'Signing in…');
    const payload = {
      username: qs('username').value.trim(),
      password: qs('password').value,
    };
    try {
      const data = await fetchJson('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      handleLoginSuccess(data.user);
    } catch (err) {
      setStatus(qs('auth-status'), err.message, true);
    }
  });

  const jellyfinBtn = qs('jellyfin-login-btn');
  if (jellyfinBtn) {
    jellyfinBtn.addEventListener('click', () => loginWithJellyfin());
  }

  qs('logout-btn').addEventListener('click', async () => {
    await fetchJson('/api/auth/logout', { method: 'POST' }).catch(() => {});
    state.user = null;
    sessionStorage.removeItem('user');
    state.playlists = [];
    state.channels = [];
    destroyPlayer();
    stopWatch();
    updateUserUI();
  });
};

const bindUpload = () => {
  const formEl = qs('upload-form');
  if (!formEl) return;
  formEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = new FormData(formEl);
    setStatus(qs('upload-status'), 'Uploading…');
    try {
      const res = await fetch('/api/playlists', {
        method: 'POST',
        body: form,
        credentials: 'same-origin',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Upload failed');
      setStatus(qs('upload-status'), `Uploaded ${data.name} (${data.channels} channels)`);
      formEl.reset();
      loadPlaylists();
    } catch (err) {
      setStatus(qs('upload-status'), err.message, true);
    }
  });
};

const bindSearch = () => {
  qs('channel-search').addEventListener('input', (e) => {
    renderChannels(e.target.value);
  });
};

const bindChannelToggle = () => {
  // channel toggle removed
};

const bindRefresh = () => {
  const btn = qs('refresh-btn');
  if (!btn) return;
  btn.addEventListener('click', () => loadPlaylists());
};

document.addEventListener('DOMContentLoaded', () => {
  ['auth-card', 'app-card'].forEach((id) => { els[id] = qs(id); });
  bindPlayerControls();
  bindAuth();
  bindUpload();
  bindSearch();
  bindChannelToggle();
  bindRefresh();
  refreshSession();
  updateViewerBadge();

  // Presence + viewer stats polling
  setInterval(() => {
    if (!state.user) return;
    fetchJson('/api/activity', {
      method: 'POST',
      body: JSON.stringify({ page: 'home' }),
    }).catch(() => {});
    loadViewerStats().catch(() => {});
  }, 15000);
});

