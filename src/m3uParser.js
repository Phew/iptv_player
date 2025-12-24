const cleanup = (value) => value ? value.trim() : '';

const extractAttr = (line, key) => {
  const match = line.match(new RegExp(`${key}="([^"]*)"`, 'i'));
  return match ? cleanup(match[1]) : '';
};

const isHttp = (value) => /^https?:\/\//i.test(value || '');

const parseM3U = (content = '') => {
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const channels = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.startsWith('#EXTINF')) continue;

    const namePart = line.split(',', 2)[1] || 'Unknown';
    let group = extractAttr(line, 'group-title');

    // Walk ahead to find group overrides (#EXTGRP), VLC opts, and the first non-comment URL
    let j = i + 1;
    let userAgent = '';
    let referer = '';
    
    while (j < lines.length && lines[j].startsWith('#')) {
      const l = lines[j];
      if (!group && l.startsWith('#EXTGRP')) {
        group = cleanup(l.replace('#EXTGRP:', ''));
      }
      if (l.startsWith('#EXTVLCOPT:')) {
        const opt = l.replace('#EXTVLCOPT:', '').trim();
        if (opt.toLowerCase().startsWith('http-user-agent=')) {
          userAgent = opt.substring('http-user-agent='.length).trim();
        }
        const optLc = opt.toLowerCase();
        if (optLc.startsWith('http-referrer=')) {
          referer = opt.substring('http-referrer='.length).trim();
        }
        if (optLc.startsWith('http-referer=')) {
          referer = opt.substring('http-referer='.length).trim();
        }
      }
      j += 1;
    }

    const url = lines[j] || '';
    if (!isHttp(url)) continue;

    channels.push({
      name: cleanup(namePart),
      url: cleanup(url),
      logo: extractAttr(line, 'tvg-logo'),
      group: group || extractAttr(line, 'group-title'),
      tvgId: extractAttr(line, 'tvg-id'),
      userAgent,
      referer,
    });
  }

  return channels;
};

module.exports = { parseM3U };

