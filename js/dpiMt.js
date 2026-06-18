#!/usr/bin/env node
'use strict';

// ============================================================================
// dpiMt.js  -  "DPI Engine v2.0": a load-balanced, multi-stage pipeline.
//
// The pipeline is Reader -> Load Balancers -> Fast Paths -> Output. It runs on
// a single thread: consistent hashing pins every packet of a flow to the same
// Fast Path, so each flow's classification, blocking decision and the per-stage
// counters are fully determined by the five-tuple hash, independent of timing.
// Each stage is a cooperating object (Rules / Stats / FastPath / LoadBalancer /
// DPIEngine) and is invoked as a direct synchronous call. Forwarded packets are
// emitted to the output pcap in input order.
//
//   node dpiMt.js <input.pcap> <output.pcap> [options]
// ============================================================================

const fs = require('fs');

const { PcapReader } = require('./lib/pcapReader');
const { PacketParser } = require('./lib/packetParser');
const { SNIExtractor, HTTPHostExtractor } = require('./lib/sniExtractor');
const {
  AppType, appTypeToString, sniToAppType, parseIP, fiveTupleKey, fiveTupleHash,
} = require('./lib/types');

const out = (s) => process.stdout.write(s);
const err = (s) => process.stderr.write(s);

// ----------------------------------------------------------------------------
// Blocking rules
// ----------------------------------------------------------------------------
class Rules {
  constructor() {
    this.blockedIps = new Set();
    this.blockedApps = new Set();
    this.blockedDomains = [];
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

// ----------------------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------------------
class Stats {
  constructor() {
    this.totalPackets = 0;
    this.totalBytes = 0;
    this.forwarded = 0;
    this.dropped = 0;
    this.tcpPackets = 0;
    this.udpPackets = 0;
    this.appCounts = new Map();    // AppType -> count
    this.detectedSnis = new Map(); // sni -> AppType
  }

  recordApp(app, sni) {
    this.appCounts.set(app, (this.appCounts.get(app) || 0) + 1);
    if (sni !== '') this.detectedSnis.set(sni, app);
  }
}

// ----------------------------------------------------------------------------
// Fast Path processor. Each Fast Path owns its own flow table.
// ----------------------------------------------------------------------------
class FastPath {
  constructor(id, rules, stats, outputPackets) {
    this.id = id;
    this.rules = rules;
    this.stats = stats;
    this.outputPackets = outputPackets; // shared sink, written in arrival order
    this.flows = new Map();
    this.processed = 0;
  }

  process(pkt) {
    this.processed++;

    const key = fiveTupleKey(pkt.tuple);
    let flow = this.flows.get(key);
    if (!flow) {
      flow = {
        tuple: pkt.tuple, appType: AppType.UNKNOWN, sni: '',
        packets: 0, bytes: 0, blocked: false, classified: false,
      };
      this.flows.set(key, flow);
    }
    flow.packets++;
    flow.bytes += pkt.data.length;

    if (!flow.classified) {
      this.classifyFlow(pkt, flow);
    }

    if (!flow.blocked) {
      flow.blocked = this.rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni);
    }

    this.stats.recordApp(flow.appType, flow.sni);

    if (flow.blocked) {
      this.stats.dropped++;
    } else {
      this.stats.forwarded++;
      this.outputPackets.push(pkt);
    }
  }

  classifyFlow(pkt, flow) {
    // TLS SNI (HTTPS, port 443).
    if (pkt.tuple.dstPort === 443 && pkt.payloadLength > 5) {
      const payload = pkt.data.subarray(pkt.payloadOffset);
      const sni = SNIExtractor.extract(payload, pkt.payloadLength);
      if (sni) {
        flow.sni = sni;
        flow.appType = sniToAppType(sni);
        flow.classified = true;
        return;
      }
    }

    // HTTP Host (port 80).
    if (pkt.tuple.dstPort === 80 && pkt.payloadLength > 10) {
      const payload = pkt.data.subarray(pkt.payloadOffset);
      const host = HTTPHostExtractor.extract(payload, pkt.payloadLength);
      if (host) {
        flow.sni = host;
        flow.appType = sniToAppType(host);
        flow.classified = true;
        return;
      }
    }

    // DNS (port 53).
    if (pkt.tuple.dstPort === 53 || pkt.tuple.srcPort === 53) {
      flow.appType = AppType.DNS;
      flow.classified = true;
      return;
    }

    // Port-based fallback (not marked classified -- may still get an SNI later).
    if (pkt.tuple.dstPort === 443) {
      flow.appType = AppType.HTTPS;
    } else if (pkt.tuple.dstPort === 80) {
      flow.appType = AppType.HTTP;
    }
  }
}

// ----------------------------------------------------------------------------
// Load Balancer. Routes each packet to one of its Fast Paths via consistent
// hashing.
// ----------------------------------------------------------------------------
class LoadBalancer {
  constructor(id, fps) {
    this.id = id;
    this.fps = fps;
    this.numFps = fps.length;
    this.dispatched = 0;
  }

  dispatch(pkt) {
    const fpIdx = Number(fiveTupleHash(pkt.tuple) % BigInt(this.numFps));
    this.fps[fpIdx].process(pkt);
    this.dispatched++;
  }
}

// ----------------------------------------------------------------------------
// DPI Engine
// ----------------------------------------------------------------------------
class DPIEngine {
  constructor(config) {
    this.config = config;
    this.rules = new Rules();
    this.stats = new Stats();
    this.outputPackets = [];
    this.fps = [];
    this.lbs = [];

    const totalFps = config.numLbs * config.fpsPerLb;

    out('\n');
    out('╔══════════════════════════════════════════════════════════════╗\n');
    out('║              DPI ENGINE v2.0 (Multi-threaded)                 ║\n');
    out('╠══════════════════════════════════════════════════════════════╣\n');
    out('║ Load Balancers: ' + String(config.numLbs).padStart(2) +
        '    FPs per LB: ' + String(config.fpsPerLb).padStart(2) +
        '    Total FPs: ' + String(totalFps).padStart(2) + '     ║\n');
    out('╚══════════════════════════════════════════════════════════════╝\n\n');

    // Create Fast Paths.
    for (let i = 0; i < totalFps; i++) {
      this.fps.push(new FastPath(i, this.rules, this.stats, this.outputPackets));
    }

    // Create Load Balancers, each owning a contiguous subset of Fast Paths.
    for (let lb = 0; lb < config.numLbs; lb++) {
      const start = lb * config.fpsPerLb;
      const lbFps = [];
      for (let i = 0; i < config.fpsPerLb; i++) {
        lbFps.push(this.fps[start + i]);
      }
      this.lbs.push(new LoadBalancer(lb, lbFps));
    }
  }

  blockIP(ip) { this.rules.blockIP(ip); }
  blockApp(app) { this.rules.blockApp(app); }
  blockDomain(dom) { this.rules.blockDomain(dom); }

  process(inputFile, outputFile) {
    const reader = new PcapReader();
    if (!reader.open(inputFile)) return false;

    const chunks = [reader.globalHeaderBytes];

    out('[Reader] Processing packets...\n');

    let pktId = 0;
    let raw;
    while ((raw = reader.readNextPacket()) !== null) {
      const parsed = PacketParser.parse(raw);
      if (!parsed) continue;
      if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

      const data = raw.data;
      const pkt = {
        id: pktId++,
        tsSec: raw.header.tsSec,
        tsUsec: raw.header.tsUsec,
        tcpFlags: parsed.tcpFlags,
        data,
        tuple: {
          srcIp: parseIP(parsed.srcIp),
          dstIp: parseIP(parsed.destIp),
          srcPort: parsed.srcPort,
          dstPort: parsed.destPort,
          protocol: parsed.protocol,
        },
        payloadOffset: 14,
        payloadLength: 0,
      };

      // Compute payload offset/length.
      if (data.length > 14) {
        const ipIhl = data[14] & 0x0f;
        pkt.payloadOffset += ipIhl * 4;

        if (parsed.hasTcp && pkt.payloadOffset + 12 < data.length) {
          const tcpOff = (data[pkt.payloadOffset + 12] >> 4) & 0x0f;
          pkt.payloadOffset += tcpOff * 4;
        } else if (parsed.hasUdp) {
          pkt.payloadOffset += 8;
        }

        pkt.payloadLength = pkt.payloadOffset < data.length
          ? data.length - pkt.payloadOffset
          : 0;
      }

      // Update reader-side stats.
      this.stats.totalPackets++;
      this.stats.totalBytes += data.length;
      if (parsed.hasTcp) this.stats.tcpPackets++;
      else if (parsed.hasUdp) this.stats.udpPackets++;

      // Dispatch to a Load Balancer (consistent hashing).
      const lbIdx = Number(fiveTupleHash(pkt.tuple) % BigInt(this.lbs.length));
      this.lbs[lbIdx].dispatch(pkt);
    }

    out(`[Reader] Done reading ${pktId} packets\n`);
    reader.close();

    // Write forwarded packets (in input order).
    for (const pkt of this.outputPackets) {
      chunks.push(packetHeaderBuffer(pkt.tsSec, pkt.tsUsec, pkt.data.length, reader.littleEndian));
      chunks.push(pkt.data);
    }
    fs.writeFileSync(outputFile, Buffer.concat(chunks));

    this.printReport();
    return true;
  }

  printReport() {
    out('\n');
    out('╔══════════════════════════════════════════════════════════════╗\n');
    out('║                      PROCESSING REPORT                        ║\n');
    out('╠══════════════════════════════════════════════════════════════╣\n');
    out(`║ Total Packets:      ${String(this.stats.totalPackets).padStart(12)}                           ║\n`);
    out(`║ Total Bytes:        ${String(this.stats.totalBytes).padStart(12)}                           ║\n`);
    out(`║ TCP Packets:        ${String(this.stats.tcpPackets).padStart(12)}                           ║\n`);
    out(`║ UDP Packets:        ${String(this.stats.udpPackets).padStart(12)}                           ║\n`);
    out('╠══════════════════════════════════════════════════════════════╣\n');
    out(`║ Forwarded:          ${String(this.stats.forwarded).padStart(12)}                           ║\n`);
    out(`║ Dropped:            ${String(this.stats.dropped).padStart(12)}                           ║\n`);

    out('╠══════════════════════════════════════════════════════════════╣\n');
    out('║ THREAD STATISTICS                                             ║\n');
    for (let i = 0; i < this.lbs.length; i++) {
      out(`║   LB${i} dispatched:   ${String(this.lbs[i].dispatched).padStart(12)}                           ║\n`);
    }
    for (let i = 0; i < this.fps.length; i++) {
      out(`║   FP${i} processed:    ${String(this.fps[i].processed).padStart(12)}                           ║\n`);
    }

    out('╠══════════════════════════════════════════════════════════════╣\n');
    out('║                   APPLICATION BREAKDOWN                       ║\n');
    out('╠══════════════════════════════════════════════════════════════╣\n');

    const sortedApps = [...this.stats.appCounts.entries()].sort((a, b) => b[1] - a[1]);
    const total = this.stats.totalPackets;
    for (const [app, count] of sortedApps) {
      const pct = total > 0 ? (100.0 * count) / total : 0;
      const barLen = Math.trunc(pct / 5);
      const bar = '#'.repeat(barLen);
      out('║ ' + appTypeToString(app).padEnd(15) +
          String(count).padStart(8) + ' ' +
          pct.toFixed(1).padStart(5) + '% ' +
          bar.padEnd(20) + '  ║\n');
    }

    out('╚══════════════════════════════════════════════════════════════╝\n');

    if (this.stats.detectedSnis.size > 0) {
      out('\n[Detected Domains/SNIs]\n');
      for (const [sni, app] of this.stats.detectedSnis) {
        out(`  - ${sni} -> ${appTypeToString(app)}\n`);
      }
    }
  }
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

function printUsage(prog) {
  out(`
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage: ${prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Example:
  ${prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
`);
}

function main(argv) {
  const prog = 'node dpiMt.js';
  if (argv.length < 2) {
    printUsage(prog);
    return 1;
  }

  const input = argv[0];
  const output = argv[1];

  const config = { numLbs: 2, fpsPerLb: 2 };
  const blockIps = [];
  const blockApps = [];
  const blockDomains = [];

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--block-ip' && i + 1 < argv.length) blockIps.push(argv[++i]);
    else if (arg === '--block-app' && i + 1 < argv.length) blockApps.push(argv[++i]);
    else if (arg === '--block-domain' && i + 1 < argv.length) blockDomains.push(argv[++i]);
    else if (arg === '--lbs' && i + 1 < argv.length) config.numLbs = parseInt(argv[++i], 10);
    else if (arg === '--fps' && i + 1 < argv.length) config.fpsPerLb = parseInt(argv[++i], 10);
  }

  const engine = new DPIEngine(config);

  for (const ip of blockIps) engine.blockIP(ip);
  for (const app of blockApps) engine.blockApp(app);
  for (const dom of blockDomains) engine.blockDomain(dom);

  if (!engine.process(input, output)) {
    return 1;
  }

  out(`\nOutput written to: ${output}\n`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
