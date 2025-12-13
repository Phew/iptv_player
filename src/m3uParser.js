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

    // Walk ahead to find group overrides (#EXTGRP) and the first non-comment URL
    let j = i + 1;
    while (j < lines.length && lines[j].startsWith('#')) {
      if (!group && lines[j].startsWith('#EXTGRP')) {
        group = cleanup(lines[j].replace('#EXTGRP:', ''));
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
    });
  }

  return channels;
};

module.exports = { parseM3U };

