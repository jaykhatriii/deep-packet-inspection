'use strict';

// ============================================================================
// types.js  -  Core data structures shared by both DPI engines:
//   - The five-tuple key/hash used to identify and load-balance flows
//   - The AppType enumeration and its string names
//   - sniToAppType(): maps a domain/SNI string to an application
// ============================================================================

// ----------------------------------------------------------------------------
// Application classification enum.
//
// The blocking-rule code iterates 0..APP_COUNT and matches an application by
// the string name returned from appTypeToString(), so this ordering is part of
// the contract.
// ----------------------------------------------------------------------------
const AppType = Object.freeze({
  UNKNOWN: 0,
  HTTP: 1,
  HTTPS: 2,
  DNS: 3,
  TLS: 4,
  QUIC: 5,
  // Specific applications (detected via SNI)
  GOOGLE: 6,
  FACEBOOK: 7,
  YOUTUBE: 8,
  TWITTER: 9,
  INSTAGRAM: 10,
  NETFLIX: 11,
  AMAZON: 12,
  MICROSOFT: 13,
  APPLE: 14,
  WHATSAPP: 15,
  TELEGRAM: 16,
  TIKTOK: 17,
  SPOTIFY: 18,
  ZOOM: 19,
  DISCORD: 20,
  GITHUB: 21,
  CLOUDFLARE: 22,
  APP_COUNT: 23, // Keep this last for counting
});

function appTypeToString(type) {
  switch (type) {
    case AppType.UNKNOWN:    return 'Unknown';
    case AppType.HTTP:       return 'HTTP';
    case AppType.HTTPS:      return 'HTTPS';
    case AppType.DNS:        return 'DNS';
    case AppType.TLS:        return 'TLS';
    case AppType.QUIC:       return 'QUIC';
    case AppType.GOOGLE:     return 'Google';
    case AppType.FACEBOOK:   return 'Facebook';
    case AppType.YOUTUBE:    return 'YouTube';
    case AppType.TWITTER:    return 'Twitter/X';
    case AppType.INSTAGRAM:  return 'Instagram';
    case AppType.NETFLIX:    return 'Netflix';
    case AppType.AMAZON:     return 'Amazon';
    case AppType.MICROSOFT:  return 'Microsoft';
    case AppType.APPLE:      return 'Apple';
    case AppType.WHATSAPP:   return 'WhatsApp';
    case AppType.TELEGRAM:   return 'Telegram';
    case AppType.TIKTOK:     return 'TikTok';
    case AppType.SPOTIFY:    return 'Spotify';
    case AppType.ZOOM:       return 'Zoom';
    case AppType.DISCORD:    return 'Discord';
    case AppType.GITHUB:     return 'GitHub';
    case AppType.CLOUDFLARE: return 'Cloudflare';
    default:                 return 'Unknown';
  }
}

// ----------------------------------------------------------------------------
// Map an SNI/domain string to an application type.
//
// The order matters: the first matching pattern wins. Note that the substring
// tests have quirks worth being aware of -- e.g. "www.netflix.com" matches the
// Twitter pattern "x.com" (via "netfli...x.com") and "www.microsoft.com"
// matches "t.co" (via "microsof...t.co...m").
// ----------------------------------------------------------------------------
function sniToAppType(sni) {
  if (!sni) return AppType.UNKNOWN;

  const s = sni.toLowerCase();
  const has = (needle) => s.indexOf(needle) !== -1;

  // Google (including general Google infrastructure)
  if (has('google') || has('gstatic') || has('googleapis') ||
      has('ggpht') || has('gvt1')) {
    return AppType.GOOGLE;
  }

  // YouTube
  if (has('youtube') || has('ytimg') || has('youtu.be') || has('yt3.ggpht')) {
    return AppType.YOUTUBE;
  }

  // Facebook/Meta
  if (has('facebook') || has('fbcdn') || has('fb.com') ||
      has('fbsbx') || has('meta.com')) {
    return AppType.FACEBOOK;
  }

  // Instagram (owned by Meta)
  if (has('instagram') || has('cdninstagram')) {
    return AppType.INSTAGRAM;
  }

  // WhatsApp (owned by Meta)
  if (has('whatsapp') || has('wa.me')) {
    return AppType.WHATSAPP;
  }

  // Twitter/X
  if (has('twitter') || has('twimg') || has('x.com') || has('t.co')) {
    return AppType.TWITTER;
  }

  // Netflix
  if (has('netflix') || has('nflxvideo') || has('nflximg')) {
    return AppType.NETFLIX;
  }

  // Amazon
  if (has('amazon') || has('amazonaws') || has('cloudfront') || has('aws')) {
    return AppType.AMAZON;
  }

  // Microsoft
  if (has('microsoft') || has('msn.com') || has('office') || has('azure') ||
      has('live.com') || has('outlook') || has('bing')) {
    return AppType.MICROSOFT;
  }

  // Apple
  if (has('apple') || has('icloud') || has('mzstatic') || has('itunes')) {
    return AppType.APPLE;
  }

  // Telegram
  if (has('telegram') || has('t.me')) {
    return AppType.TELEGRAM;
  }

  // TikTok
  if (has('tiktok') || has('tiktokcdn') || has('musical.ly') || has('bytedance')) {
    return AppType.TIKTOK;
  }

  // Spotify
  if (has('spotify') || has('scdn.co')) {
    return AppType.SPOTIFY;
  }

  // Zoom
  if (has('zoom')) {
    return AppType.ZOOM;
  }

  // Discord
  if (has('discord') || has('discordapp')) {
    return AppType.DISCORD;
  }

  // GitHub
  if (has('github') || has('githubusercontent')) {
    return AppType.GITHUB;
  }

  // Cloudflare
  if (has('cloudflare') || has('cf-')) {
    return AppType.CLOUDFLARE;
  }

  // If SNI is present but not recognized, still mark as TLS/HTTPS
  return AppType.HTTPS;
}

// ----------------------------------------------------------------------------
// Five-tuple helpers.
//
// A five-tuple is a plain object: { srcIp, dstIp, srcPort, dstPort, protocol }.
// srcIp/dstIp are uint32 values produced by parseIP().
// ----------------------------------------------------------------------------

// Parse a dotted-decimal IPv4 string into a uint32 (octet 0 in the low byte).
// The numeric value is only ever compared against itself, so the packing
// convention just has to be applied consistently.
function parseIP(ip) {
  let result = 0;
  let octet = 0;
  let shift = 0;
  for (let i = 0; i < ip.length; i++) {
    const c = ip[i];
    if (c === '.') {
      result += octet * 2 ** shift;
      shift += 8;
      octet = 0;
    } else if (c >= '0' && c <= '9') {
      octet = octet * 10 + (ip.charCodeAt(i) - 48);
    }
  }
  result += octet * 2 ** shift;
  return result >>> 0;
}

// Stable string key for using a five-tuple in a Map (JS Maps use reference
// identity for objects, so we key on a string instead).
function fiveTupleKey(t) {
  return t.srcIp + '|' + t.dstIp + '|' + t.srcPort + '|' + t.dstPort + '|' + t.protocol;
}

// ----------------------------------------------------------------------------
// Five-tuple hash used for load balancing. Computed in 64-bit unsigned
// arithmetic with BigInt so the `hash % N` distribution is stable and
// deterministic across runs and platforms.
// ----------------------------------------------------------------------------
const U64_MASK = (1n << 64n) - 1n;
const GOLDEN = 0x9e3779b9n;

function fiveTupleHash(t) {
  let h = 0n;
  const combine = (value) => {
    const term = (value + GOLDEN + ((h << 6n) & U64_MASK) + (h >> 2n)) & U64_MASK;
    h = (h ^ term) & U64_MASK;
  };
  combine(BigInt(t.srcIp >>> 0));
  combine(BigInt(t.dstIp >>> 0));
  combine(BigInt(t.srcPort & 0xffff));
  combine(BigInt(t.dstPort & 0xffff));
  combine(BigInt(t.protocol & 0xff));
  return h; // BigInt
}

module.exports = {
  AppType,
  appTypeToString,
  sniToAppType,
  parseIP,
  fiveTupleKey,
  fiveTupleHash,
};
