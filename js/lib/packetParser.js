'use strict';

// ============================================================================
// packetParser.js  -  Extracts Ethernet / IPv4 / TCP / UDP header fields from a
// raw captured packet. Network fields are big-endian, read directly with
// Buffer's BE accessors.
// ============================================================================

const Protocol = Object.freeze({ ICMP: 1, TCP: 6, UDP: 17 });
const TCPFlags = Object.freeze({
  FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20,
});
const EtherType = Object.freeze({ IPv4: 0x0800, IPv6: 0x86dd, ARP: 0x0806 });

const ETH_HEADER_LEN = 14;
const MIN_IP_HEADER_LEN = 20;
const MIN_TCP_HEADER_LEN = 20;
const UDP_HEADER_LEN = 8;

const PacketParser = {
  // Parse a raw packet ({ header, data }) into a structured object, or return
  // null if the Ethernet/IP/transport headers are too short or malformed.
  parse(raw) {
    const data = raw.data;
    const len = data.length;

    const parsed = {
      timestampSec: raw.header.tsSec,
      timestampUsec: raw.header.tsUsec,
      srcMac: '',
      destMac: '',
      etherType: 0,
      hasIp: false,
      ipVersion: 0,
      srcIp: '',
      destIp: '',
      protocol: 0,
      ttl: 0,
      hasTcp: false,
      hasUdp: false,
      srcPort: 0,
      destPort: 0,
      tcpFlags: 0,
      seqNumber: 0,
      ackNumber: 0,
      payloadLength: 0,
      payloadOffset: 0,
    };

    let offset = 0;

    // --- Ethernet ---
    if (len < ETH_HEADER_LEN) return null;
    parsed.destMac = macToString(data, 0);
    parsed.srcMac = macToString(data, 6);
    parsed.etherType = data.readUInt16BE(12);
    offset = ETH_HEADER_LEN;

    // --- IPv4 ---
    if (parsed.etherType === EtherType.IPv4) {
      if (len < offset + MIN_IP_HEADER_LEN) return null;

      const versionIhl = data[offset];
      parsed.ipVersion = (versionIhl >> 4) & 0x0f;
      const ihl = versionIhl & 0x0f;

      if (parsed.ipVersion !== 4) return null;

      const ipHeaderLen = ihl * 4;
      if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset + ipHeaderLen) {
        return null;
      }

      parsed.ttl = data[offset + 8];
      parsed.protocol = data[offset + 9];
      parsed.srcIp = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
      parsed.destIp = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;
      parsed.hasIp = true;
      offset += ipHeaderLen;

      // --- Transport ---
      if (parsed.protocol === Protocol.TCP) {
        if (len < offset + MIN_TCP_HEADER_LEN) return null;
        parsed.srcPort = data.readUInt16BE(offset);
        parsed.destPort = data.readUInt16BE(offset + 2);
        parsed.seqNumber = data.readUInt32BE(offset + 4);
        parsed.ackNumber = data.readUInt32BE(offset + 8);
        const dataOffset = (data[offset + 12] >> 4) & 0x0f;
        const tcpHeaderLen = dataOffset * 4;
        parsed.tcpFlags = data[offset + 13];
        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset + tcpHeaderLen) {
          return null;
        }
        parsed.hasTcp = true;
        offset += tcpHeaderLen;
      } else if (parsed.protocol === Protocol.UDP) {
        if (len < offset + UDP_HEADER_LEN) return null;
        parsed.srcPort = data.readUInt16BE(offset);
        parsed.destPort = data.readUInt16BE(offset + 2);
        parsed.hasUdp = true;
        offset += UDP_HEADER_LEN;
      }
    }

    // --- Payload ---
    if (offset < len) {
      parsed.payloadLength = len - offset;
      parsed.payloadOffset = offset;
    } else {
      parsed.payloadLength = 0;
      parsed.payloadOffset = offset;
    }

    return parsed;
  },
};

function macToString(buf, start) {
  const parts = [];
  for (let i = 0; i < 6; i++) {
    parts.push(buf[start + i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

// Format a uint32 IP as dotted decimal (octet 0 in the low byte). The parser
// builds the dotted string directly; this helper is provided for convenience.
function ipToString(ip) {
  return `${(ip >>> 0) & 0xff}.${(ip >>> 8) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 24) & 0xff}`;
}

function protocolToString(protocol) {
  switch (protocol) {
    case Protocol.ICMP: return 'ICMP';
    case Protocol.TCP:  return 'TCP';
    case Protocol.UDP:  return 'UDP';
    default:            return `Unknown(${protocol})`;
  }
}

function tcpFlagsToString(flags) {
  let result = '';
  if (flags & TCPFlags.SYN) result += 'SYN ';
  if (flags & TCPFlags.ACK) result += 'ACK ';
  if (flags & TCPFlags.FIN) result += 'FIN ';
  if (flags & TCPFlags.RST) result += 'RST ';
  if (flags & TCPFlags.PSH) result += 'PSH ';
  if (flags & TCPFlags.URG) result += 'URG ';
  result = result.trimEnd();
  return result === '' ? 'none' : result;
}

module.exports = {
  PacketParser,
  Protocol,
  TCPFlags,
  EtherType,
  macToString,
  ipToString,
  protocolToString,
  tcpFlagsToString,
};
