'use strict';

// ============================================================================
// sniExtractor.js  -  Deep-packet-inspection extractors for application
// identification:
//   - SNIExtractor:       Server Name Indication from a TLS Client Hello
//   - HTTPHostExtractor:  Host header from a plaintext HTTP request
//   - DNSExtractor:       queried domain from a DNS request
//   - QUICSNIExtractor:   best-effort SNI from a QUIC Initial packet
//
// `payload` is a Buffer positioned at the start of the transport payload;
// `length` is the number of valid bytes and bounds every read.
// ============================================================================

function readUint16BE(data, i) {
  return ((data[i] << 8) | data[i + 1]) & 0xffff;
}

function readUint24BE(data, i) {
  return ((data[i] << 16) | (data[i + 1] << 8) | data[i + 2]) >>> 0;
}

// ----------------------------------------------------------------------------
// TLS SNI Extractor
// ----------------------------------------------------------------------------
const CONTENT_TYPE_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const EXTENSION_SNI = 0x0000;
const SNI_TYPE_HOSTNAME = 0x00;

const SNIExtractor = {
  isTLSClientHello(payload, length) {
    // Minimum: 5-byte record header + 4-byte handshake header.
    if (length < 9) return false;

    // Byte 0: content type must be Handshake.
    if (payload[0] !== CONTENT_TYPE_HANDSHAKE) return false;

    // Bytes 1-2: TLS version, accept SSL 3.0 (0x0300) .. TLS 1.3 (0x0304).
    const version = readUint16BE(payload, 1);
    if (version < 0x0300 || version > 0x0304) return false;

    // Bytes 3-4: record length must fit inside the buffer.
    const recordLength = readUint16BE(payload, 3);
    if (recordLength > length - 5) return false;

    // Byte 5: handshake type must be Client Hello.
    if (payload[5] !== HANDSHAKE_CLIENT_HELLO) return false;

    return true;
  },

  extract(payload, length) {
    if (!this.isTLSClientHello(payload, length)) return null;

    let offset = 5; // skip TLS record header

    // Handshake header: 1-byte type (checked) + 3-byte length.
    offset += 4;

    // Client Hello body
    offset += 2;  // client version
    offset += 32; // random

    // Session ID
    if (offset >= length) return null;
    const sessionIdLength = payload[offset];
    offset += 1 + sessionIdLength;

    // Cipher suites
    if (offset + 2 > length) return null;
    const cipherSuitesLength = readUint16BE(payload, offset);
    offset += 2 + cipherSuitesLength;

    // Compression methods
    if (offset >= length) return null;
    const compressionMethodsLength = payload[offset];
    offset += 1 + compressionMethodsLength;

    // Extensions
    if (offset + 2 > length) return null;
    const extensionsLength = readUint16BE(payload, offset);
    offset += 2;

    let extensionsEnd = offset + extensionsLength;
    if (extensionsEnd > length) {
      extensionsEnd = length; // truncated, but try to parse anyway
    }

    while (offset + 4 <= extensionsEnd) {
      const extensionType = readUint16BE(payload, offset);
      const extensionLength = readUint16BE(payload, offset + 2);
      offset += 4;

      if (offset + extensionLength > extensionsEnd) break;

      if (extensionType === EXTENSION_SNI) {
        // SNI extension layout:
        //   SNI List Length (2) | SNI Type (1) | SNI Length (2) | SNI Value
        if (extensionLength < 5) break;

        const sniListLength = readUint16BE(payload, offset);
        if (sniListLength < 3) break;

        const sniType = payload[offset + 2];
        const sniLength = readUint16BE(payload, offset + 3);

        if (sniType !== SNI_TYPE_HOSTNAME) break;
        if (sniLength > extensionLength - 5) break;

        return payload.toString('latin1', offset + 5, offset + 5 + sniLength);
      }

      offset += extensionLength;
    }

    return null;
  },
};

// ----------------------------------------------------------------------------
// HTTP Host Header Extractor
// ----------------------------------------------------------------------------
const HTTP_METHODS = ['GET ', 'POST', 'PUT ', 'HEAD', 'DELE', 'PATC', 'OPTI'];

const HTTPHostExtractor = {
  isHTTPRequest(payload, length) {
    if (length < 4) return false;
    const prefix = payload.toString('latin1', 0, 4);
    return HTTP_METHODS.indexOf(prefix) !== -1;
  },

  extract(payload, length) {
    if (!this.isHTTPRequest(payload, length)) return null;

    const HOST_HEADER_LEN = 6; // "Host: "
    for (let i = 0; i + HOST_HEADER_LEN < length; i++) {
      // Case-insensitive match of "Host:".
      if ((payload[i] === 0x48 || payload[i] === 0x68) &&       // H / h
          (payload[i + 1] === 0x6f || payload[i + 1] === 0x4f) && // o / O
          (payload[i + 2] === 0x73 || payload[i + 2] === 0x53) && // s / S
          (payload[i + 3] === 0x74 || payload[i + 3] === 0x54) && // t / T
          payload[i + 4] === 0x3a) {                              // :

        let start = i + 5;
        while (start < length && (payload[start] === 0x20 || payload[start] === 0x09)) {
          start++; // skip spaces and tabs
        }

        let end = start;
        while (end < length && payload[end] !== 0x0d && payload[end] !== 0x0a) {
          end++; // until CR or LF
        }

        if (end > start) {
          let host = payload.toString('latin1', start, end);
          const colon = host.indexOf(':');
          if (colon !== -1) host = host.substring(0, colon); // strip port
          return host;
        }
      }
    }

    return null;
  },
};

// ----------------------------------------------------------------------------
// DNS Query Extractor
// ----------------------------------------------------------------------------
const DNSExtractor = {
  isDNSQuery(payload, length) {
    if (length < 12) return false;
    // QR bit (byte 2, bit 7) must be 0 for a query.
    if (payload[2] & 0x80) return false;
    // QDCOUNT (bytes 4-5) must be > 0.
    const qdcount = readUint16BE(payload, 4);
    if (qdcount === 0) return false;
    return true;
  },

  extractQuery(payload, length) {
    if (!this.isDNSQuery(payload, length)) return null;

    let offset = 12; // DNS question section starts after the 12-byte header
    const labels = [];

    while (offset < length) {
      const labelLength = payload[offset];
      if (labelLength === 0) break;       // end of name
      if (labelLength > 63) break;        // compression pointer or invalid
      offset++;
      if (offset + labelLength > length) break;
      labels.push(payload.toString('latin1', offset, offset + labelLength));
      offset += labelLength;
    }

    const domain = labels.join('.');
    return domain === '' ? null : domain;
  },
};

// ----------------------------------------------------------------------------
// QUIC SNI Extractor (simplified, best-effort)
// ----------------------------------------------------------------------------
const QUICSNIExtractor = {
  isQUICInitial(payload, length) {
    if (length < 5) return false;
    // QUIC long header has the form bit (0x80) set.
    if ((payload[0] & 0x80) === 0) return false;
    return true;
  },

  extract(payload, length) {
    if (!this.isQUICInitial(payload, length)) return null;

    // Scan for an embedded TLS Client Hello and try to extract its SNI.
    for (let i = 0; i + 50 < length; i++) {
      if (payload[i] === 0x01 && i >= 5) { // Client Hello handshake type
        const result = SNIExtractor.extract(payload.subarray(i - 5), length - i + 5);
        if (result) return result;
      }
    }

    return null;
  },
};

module.exports = {
  SNIExtractor,
  HTTPHostExtractor,
  DNSExtractor,
  QUICSNIExtractor,
  readUint16BE,
  readUint24BE,
};
