#!/usr/bin/env node
'use strict';

// ============================================================================
// dpiSimple.js  -  Single-threaded "DPI Engine v1.0".
//
// Reads a pcap, classifies each flow via SNI / HTTP Host / DNS / port
// heuristics, applies blocking rules, writes the forwarded packets to an output
// pcap, and prints a report.
//
//   node dpiSimple.js <input.pcap> <output.pcap> [options]
// ============================================================================

const fs = require('fs');

const { PcapReader } = require('./lib/pcapReader');
const { PacketParser } = require('./lib/packetParser');
const { SNIExtractor, HTTPHostExtractor } = require('./lib/sniExtractor');
const { AppType, appTypeToString, sniToAppType, parseIP, fiveTupleKey } = require('./lib/types');

const out = (s) => process.stdout.write(s);
const err = (s) => process.stderr.write(s);

// ----------------------------------------------------------------------------
// Blocking rules
// ----------------------------------------------------------------------------
class BlockingRules {
  constructor() {
    this.blockedIps = new Set();        // uint32 IPs
    this.blockedApps = new Set();       // AppType ints
    this.blockedDomains = [];           // substring matches
  }

  blockIP(ip) {
    this.blockedIps.add(parseIP(ip));
    out(`[Rules] Blocked IP: ${ip}\n`);
  }

  blockApp(app) {
    for (let i = 0; i < AppType.APP_COUNT; i++) {
      if (appTypeToString(i) === app) {
        this.blockedApps.add(i);
        out(`[Rules] Blocked app: ${app}\n`);
        return;
      }
    }
    err(`[Rules] Unknown app: ${app}\n`);
  }

  blockDomain(domain) {
    this.blockedDomains.push(domain);
    out(`[Rules] Blocked domain: ${domain}\n`);
  }

  isBlocked(srcIp, app, sni) {
    if (this.blockedIps.has(srcIp)) return true;
    if (this.blockedApps.has(app)) return true;
    for (const dom of this.blockedDomains) {
      if (sni.indexOf(dom) !== -1) return true;
    }
    return false;
  }
}

function printUsage(prog) {
  out(`
DPI Engine - Deep Packet Inspection System
==========================================

Usage: ${prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  ${prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
`);
}

// Build a 16-byte pcap packet record header in the file's byte order.
function packetHeaderBuffer(tsSec, tsUsec, len, littleEndian) {
  const b = Buffer.allocUnsafe(16);
  if (littleEndian) {
    b.writeUInt32LE(tsSec >>> 0, 0);
    b.writeUInt32LE(tsUsec >>> 0, 4);
    b.writeUInt32LE(len >>> 0, 8);
    b.writeUInt32LE(len >>> 0, 12);
  } else {
    b.writeUInt32BE(tsSec >>> 0, 0);
    b.writeUInt32BE(tsUsec >>> 0, 4);
    b.writeUInt32BE(len >>> 0, 8);
    b.writeUInt32BE(len >>> 0, 12);
  }
  return b;
}

function main(argv) {
  const prog = 'node dpiSimple.js';
  if (argv.length < 2) {
    printUsage(prog);
    return 1;
  }

  const inputFile = argv[0];
  const outputFile = argv[1];

  const rules = new BlockingRules();

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--block-ip' && i + 1 < argv.length) {
      rules.blockIP(argv[++i]);
    } else if (arg === '--block-app' && i + 1 < argv.length) {
      rules.blockApp(argv[++i]);
    } else if (arg === '--block-domain' && i + 1 < argv.length) {
      rules.blockDomain(argv[++i]);
    }
  }

  out('\n');
  out('╔══════════════════════════════════════════════════════════════╗\n');
  out('║                    DPI ENGINE v1.0                            ║\n');
  out('╚══════════════════════════════════════════════════════════════╝\n\n');

  const reader = new PcapReader();
  if (!reader.open(inputFile)) {
    return 1;
  }

  // Output: collect chunks, write once at the end.
  const chunks = [reader.globalHeaderBytes];

  // Flow table: fiveTupleKey -> flow
  const flows = new Map();

  let totalPackets = 0;
  let forwarded = 0;
  let dropped = 0;
  const appStats = new Map(); // AppType -> count

  out('[DPI] Processing packets...\n');

  let raw;
  while ((raw = reader.readNextPacket()) !== null) {
    totalPackets++;

    const parsed = PacketParser.parse(raw);
    if (!parsed) continue;
    if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

    const data = raw.data;

    // Build five-tuple.
    const tuple = {
      srcIp: parseIP(parsed.srcIp),
      dstIp: parseIP(parsed.destIp),
      srcPort: parsed.srcPort,
      dstPort: parsed.destPort,
      protocol: parsed.protocol,
    };

    // Get or create flow.
    const key = fiveTupleKey(tuple);
    let flow = flows.get(key);
    if (!flow) {
      flow = { tuple, appType: AppType.UNKNOWN, sni: '', packets: 0, bytes: 0, blocked: false };
      flows.set(key, flow);
    }
    flow.packets++;
    flow.bytes += data.length;

    // Try SNI extraction (HTTPS, port 443) -- even for generic-HTTPS flows.
    if ((flow.appType === AppType.UNKNOWN || flow.appType === AppType.HTTPS) &&
        flow.sni === '' && parsed.hasTcp && parsed.destPort === 443) {
      let payloadOffset = 14;
      const ipIhl = data[14] & 0x0f;
      payloadOffset += ipIhl * 4;

      if (payloadOffset + 12 < data.length) {
        const tcpOffset = (data[payloadOffset + 12] >> 4) & 0x0f;
        payloadOffset += tcpOffset * 4;

        if (payloadOffset < data.length) {
          const payloadLen = data.length - payloadOffset;
          if (payloadLen > 5) {
            const sni = SNIExtractor.extract(data.subarray(payloadOffset), payloadLen);
            if (sni) {
              flow.sni = sni;
              flow.appType = sniToAppType(sni);
            }
          }
        }
      }
    }

    // HTTP Host extraction (port 80).
    if ((flow.appType === AppType.UNKNOWN || flow.appType === AppType.HTTP) &&
        flow.sni === '' && parsed.hasTcp && parsed.destPort === 80) {
      let payloadOffset = 14;
      const ipIhl = data[14] & 0x0f;
      payloadOffset += ipIhl * 4;

      if (payloadOffset + 12 < data.length) {
        const tcpOffset = (data[payloadOffset + 12] >> 4) & 0x0f;
        payloadOffset += tcpOffset * 4;

        if (payloadOffset < data.length) {
          const payloadLen = data.length - payloadOffset;
          const host = HTTPHostExtractor.extract(data.subarray(payloadOffset), payloadLen);
          if (host) {
            flow.sni = host;
            flow.appType = sniToAppType(host);
          }
        }
      }
    }

    // DNS classification (port 53).
    if (flow.appType === AppType.UNKNOWN &&
        (parsed.destPort === 53 || parsed.srcPort === 53)) {
      flow.appType = AppType.DNS;
    }

    // Port-based fallback.
    if (flow.appType === AppType.UNKNOWN) {
      if (parsed.destPort === 443) flow.appType = AppType.HTTPS;
      else if (parsed.destPort === 80) flow.appType = AppType.HTTP;
    }

    // Check blocking rules (once per flow).
    if (!flow.blocked) {
      flow.blocked = rules.isBlocked(tuple.srcIp, flow.appType, flow.sni);
      if (flow.blocked) {
        let line = `[BLOCKED] ${parsed.srcIp} -> ${parsed.destIp} (${appTypeToString(flow.appType)}`;
        if (flow.sni !== '') line += `: ${flow.sni}`;
        line += ')\n';
        out(line);
      }
    }

    // Update app stats.
    appStats.set(flow.appType, (appStats.get(flow.appType) || 0) + 1);

    // Forward or drop.
    if (flow.blocked) {
      dropped++;
    } else {
      forwarded++;
      chunks.push(packetHeaderBuffer(raw.header.tsSec, raw.header.tsUsec, data.length, reader.littleEndian));
      chunks.push(data);
    }
  }

  reader.close();
  fs.writeFileSync(outputFile, Buffer.concat(chunks));

  // ---- Report ----
  out('\n');
  out('╔══════════════════════════════════════════════════════════════╗\n');
  out('║                      PROCESSING REPORT                       ║\n');
  out('╠══════════════════════════════════════════════════════════════╣\n');
  out(`║ Total Packets:      ${String(totalPackets).padStart(10)}                             ║\n`);
  out(`║ Forwarded:          ${String(forwarded).padStart(10)}                             ║\n`);
  out(`║ Dropped:            ${String(dropped).padStart(10)}                             ║\n`);
  out(`║ Active Flows:       ${String(flows.size).padStart(10)}                             ║\n`);
  out('╠══════════════════════════════════════════════════════════════╣\n');
  out('║                    APPLICATION BREAKDOWN                     ║\n');
  out('╠══════════════════════════════════════════════════════════════╣\n');

  const sortedApps = [...appStats.entries()].sort((a, b) => b[1] - a[1]);
  for (const [app, count] of sortedApps) {
    const pct = (100.0 * count) / totalPackets;
    const barLen = Math.trunc(pct / 5);
    const bar = '#'.repeat(barLen);
    out('║ ' + appTypeToString(app).padEnd(15) +
        String(count).padStart(8) + ' ' +
        pct.toFixed(1).padStart(5) + '% ' +
        bar.padEnd(20) + '  ║\n');
  }

  out('╚══════════════════════════════════════════════════════════════╝\n');

  // List unique SNIs.
  out('\n[Detected Applications/Domains]\n');
  const uniqueSnis = new Map(); // sni -> appType
  for (const flow of flows.values()) {
    if (flow.sni !== '') uniqueSnis.set(flow.sni, flow.appType);
  }
  for (const [sni, app] of uniqueSnis) {
    out(`  - ${sni} -> ${appTypeToString(app)}\n`);
  }

  out(`\nOutput written to: ${outputFile}\n`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
