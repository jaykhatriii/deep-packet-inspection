# DPI Engine - Deep Packet Inspection System (JavaScript)

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

> **Note:** This project is written in **JavaScript (Node.js)** with no external dependencies (pure Node.js, `>= 14`).

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `js/dpiSimple.js` | Learning, small captures |
| Load-balanced pipeline | `js/dpiMt.js` | The full Reader → LB → FP → Output architecture |

> **About the "multi-threaded" version:** `js/dpiMt.js` models a load-balanced pipeline (Reader → Load Balancers → Fast Paths → Output) on a single thread. Consistent hashing pins every packet of a flow to the same Fast Path, so each flow's result is fully determined by the five-tuple hash, regardless of timing. The report includes per-stage ("thread") statistics showing how flows are distributed.

---

## 4. File Structure

```
deep_packet_inspection/
├── js/
│   ├── lib/                     # Shared modules
│   │   ├── types.js             # Data structures (FiveTuple, AppType, hashing)
│   │   ├── pcapReader.js        # PCAP file reading
│   │   ├── packetParser.js      # Network protocol parsing
│   │   └── sniExtractor.js      # TLS/HTTP/DNS/QUIC inspection
│   │
│   ├── dpiSimple.js             # ★ SIMPLE VERSION ★
│   ├── dpiMt.js                 # ★ MULTI-THREADED MODEL ★
│   ├── package.json
│   └── README.md                # JS-specific notes & verification details
│
├── generate_test_pcap.py        # Creates test data (Python helper)
├── test_dpi.pcap                # Sample capture with various traffic
└── README.md                    # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `js/dpiSimple.js`:

### Step 1: Read PCAP File

```js
const reader = new PcapReader();
reader.open('capture.pcap');
```

**What happens:**
1. Read the file into a buffer
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file and detect its byte order

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```js
let raw;
while ((raw = reader.readNextPacket()) !== null) {
    // raw.data contains the packet bytes (a Buffer)
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.inclLen)
3. Return `null` when no more packets

### Step 3: Parse Protocol Headers

```js
const parsed = PacketParser.parse(raw);
```

**What happens (in packetParser.js):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.srcMac  = "00:11:22:33:44:55"
parsed.destMac = "aa:bb:cc:dd:ee:ff"
parsed.srcIp   = "192.168.1.100"
parsed.destIp  = "172.217.14.206"
parsed.srcPort = 54321
parsed.destPort = 443
parsed.protocol = 6 (TCP)
parsed.hasTcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```js
const tuple = {
    srcIp: parseIP(parsed.srcIp),
    dstIp: parseIP(parsed.destIp),
    srcPort: parsed.srcPort,
    dstPort: parsed.destPort,
    protocol: parsed.protocol,
};

const key = fiveTupleKey(tuple);
let flow = flows.get(key);          // Get or create
```

**What happens:**
- The flow table is a `Map`: `fiveTupleKey → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```js
// For HTTPS traffic (port 443)
if (parsed.destPort === 443 && payloadLen > 5) {
    const sni = SNIExtractor.extract(payload, payloadLen);
    if (sni) {
        flow.sni = sni;                       // "www.youtube.com"
        flow.appType = sniToAppType(sni);     // AppType.YOUTUBE
    }
}
```

**What happens (in sniExtractor.js):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```js
   // In types.js
   if (s.indexOf('youtube') !== -1) {
       return AppType.YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```js
if (rules.isBlocked(tuple.srcIp, flow.appType, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```js
// Check IP blacklist
if (this.blockedIps.has(srcIp)) return true;

// Check app blacklist
if (this.blockedApps.has(app)) return true;

// Check domain blacklist (substring match)
for (const dom of this.blockedDomains) {
    if (sni.indexOf(dom) !== -1) return true;
}

return false;
```

### Step 7: Forward or Drop

```js
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output buffer
    chunks.push(packetHeaderBuffer(...));
    chunks.push(raw.data);
}
```

### Step 8: Generate Report

After processing all packets:
```js
// Count apps (done per packet during processing)
appStats.set(flow.appType, (appStats.get(flow.appType) || 0) + 1);

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The pipeline engine (`js/dpiMt.js`) implements a **load-balanced parallel architecture** as a set of cooperating objects:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader (loop)  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0            │           │  LB1            │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0       │ │FP1       │   │FP2       │ │FP3       │
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output (in order)    │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing, each with its own flow table
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):          hash → FP2
Packet 2 (SYN-ACK):      hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):         hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

The five-tuple hash is computed in 64-bit unsigned arithmetic (`BigInt`), so `hash % N` routes packets deterministically — the "THREAD STATISTICS" in the report are stable for any `--lbs` / `--fps` configuration.

### Detailed Flow

#### Step 1: Reader

```js
while ((raw = reader.readNextPacket()) !== null) {
    const pkt = createPacket(raw);

    // Hash to select Load Balancer
    const lbIdx = Number(fiveTupleHash(pkt.tuple) % BigInt(this.lbs.length));

    // Hand off to that LB
    this.lbs[lbIdx].dispatch(pkt);
}
```

#### Step 2: Load Balancer

```js
dispatch(pkt) {
    // Hash to select Fast Path
    const fpIdx = Number(fiveTupleHash(pkt.tuple) % BigInt(this.numFps));

    this.fps[fpIdx].process(pkt);
    this.dispatched++;
}
```

#### Step 3: Fast Path

```js
process(pkt) {
    // Look up flow (each FP has its own flow table)
    let flow = this.flows.get(fiveTupleKey(pkt.tuple)); // get or create

    // Classify (SNI extraction)
    if (!flow.classified) this.classifyFlow(pkt, flow);

    // Check rules
    if (this.rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni)) {
        this.stats.dropped++;
    } else {
        // Forward
        this.stats.forwarded++;
        this.outputPackets.push(pkt);
    }
}
```

#### Step 4: Output

Forwarded packets are written to the output PCAP in input order:

```js
for (const pkt of this.outputPackets) {
    chunks.push(packetHeaderBuffer(pkt.tsSec, pkt.tsUsec, pkt.data.length, le));
    chunks.push(pkt.data);
}
fs.writeFileSync(outputFile, Buffer.concat(chunks));
```

> Forwarded packets are written in input order — a stable, deterministic ordering.

---

## 7. Deep Dive: Each Component

### lib/pcapReader.js

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```
Global Header (24 bytes):
    magicNumber    // 0xa1b2c3d4 identifies PCAP (and its byte order)
    versionMajor   // Usually 2
    versionMinor   // Usually 4
    snaplen        // Max packet size captured
    network        // 1 = Ethernet

Packet Header (16 bytes):
    tsSec          // Timestamp (seconds)
    tsUsec         // Timestamp (microseconds)
    inclLen        // Bytes saved in file
    origLen        // Original packet size
```

**Key methods:**
- `open(filename)`: Read PCAP, validate header, detect byte order
- `readNextPacket()`: Read next packet (returns `{ header, data }` or `null`)
- `close()`: Clean up

**Endianness:** the byte order is detected from the magic number and used for both reading and writing, so little- and big-endian capture files round-trip correctly.

### lib/packetParser.js

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```js
PacketParser.parse(raw); // -> parsed object (or null if malformed)
//   parseEthernet  -> MACs, EtherType
//   parseIPv4      -> IPs, protocol, TTL
//   parseTCP       -> ports, flags, seq/ack numbers
//   parseUDP       -> ports
```

**Network Byte Order:** Network protocols are big-endian (most significant byte first). Node's `Buffer` reads them directly:
```js
const port = data.readUInt16BE(offset);  // 16-bit big-endian
const seq  = data.readUInt32BE(offset);  // 32-bit big-endian
```

### lib/sniExtractor.js

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```js
SNIExtractor.extract(payload, length);
// 1. Verify TLS record header
// 2. Verify Client Hello handshake
// 3. Skip to extensions
// 4. Find SNI extension (type 0x0000)
// 5. Extract hostname string
```

**For HTTP:**
```js
HTTPHostExtractor.extract(payload, length);
// 1. Verify HTTP request (GET, POST, etc.)
// 2. Search for "Host: " header
// 3. Extract value until newline
```

The module also includes `DNSExtractor` and a simplified `QUICSNIExtractor`.

### lib/types.js

**Purpose:** Define data structures and helpers used throughout

**FiveTuple** (a plain object):
```js
{ srcIp, dstIp, srcPort, dstPort, protocol }
// srcIp/dstIp are uint32 values from parseIP()
// fiveTupleKey(t) builds a stable string key for use in a Map
```

**AppType** (enum-like object, values match the original ordering):
```js
const AppType = {
    UNKNOWN: 0, HTTP: 1, HTTPS: 2, DNS: 3, TLS: 4, QUIC: 5,
    GOOGLE: 6, FACEBOOK: 7, YOUTUBE: 8, TWITTER: 9, INSTAGRAM: 10,
    // ... more apps
    APP_COUNT: 23,
};
```

**sniToAppType function:**
```js
function sniToAppType(sni) {
    const s = sni.toLowerCase();
    if (s.indexOf('youtube') !== -1)  return AppType.YOUTUBE;
    if (s.indexOf('facebook') !== -1) return AppType.FACEBOOK;
    // ... more patterns
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```js
function extract(payload, length) {
    // Check TLS record header
    if (payload[0] !== 0x16) return null;   // Not handshake
    if (payload[5] !== 0x01) return null;   // Not Client Hello

    let offset = 43;  // Skip to session ID

    // Skip Session ID
    const sessionLen = payload[offset];
    offset += 1 + sessionLen;

    // Skip Cipher Suites
    const cipherLen = readUint16BE(payload, offset);
    offset += 2 + cipherLen;

    // Skip Compression Methods
    const compLen = payload[offset];
    offset += 1 + compLen;

    // Read Extensions Length
    const extLen = readUint16BE(payload, offset);
    offset += 2;

    // Search for SNI extension
    const extEnd = offset + extLen;
    while (offset + 4 <= extEnd) {
        const extType = readUint16BE(payload, offset);
        const extDataLen = readUint16BE(payload, offset + 2);
        offset += 4;

        if (extType === 0x0000) {  // SNI!
            const sniLen = readUint16BE(payload, offset + 3);
            return payload.toString('latin1', offset + 5, offset + 5 + sniLen);
        }

        offset += extDataLen;
    }

    return null;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Node.js** `>= 14` (tested on Node 26)
- No external libraries or build step needed!

### Running

**Simple version:**
```bash
node js/dpiSimple.js test_dpi.pcap output.pcap
```

**Multi-threaded model:**
```bash
node js/dpiMt.js test_dpi.pcap output.pcap
```

**With blocking:**
```bash
node js/dpiMt.js test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure thread topology (multi-threaded model only):**
```bash
node js/dpiMt.js input.pcap output.pcap --lbs 4 --fps 4
# Models 4 LBs × 4 FPs = 16 fast-path processors
```

### Options

| Flag | Meaning |
|------|---------|
| `--block-ip <ip>` | Block all traffic from a source IP |
| `--block-app <app>` | Block an application (`YouTube`, `Facebook`, `TikTok`, …) |
| `--block-domain <dom>` | Block any SNI/Host containing this substring |
| `--lbs <n>` | Load-balancer count — `dpiMt.js` only (default 2) |
| `--fps <n>` | Fast-path processors per LB — `dpiMt.js` only (default 2) |

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    70                              ║
║ Dropped:                       7                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ DNS                   4   5.2% #                              ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of LB/FP processors created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across LB/FP processors |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

> **Note on ordering:** per-app counts and detected SNIs are kept in insertion-ordered `Map`s, so the *order* of equal-count rows and the detected-domains list is stable and deterministic run to run.

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```js
   // In types.js
   if (s.indexOf('twitch') !== -1) return AppType.TWITCH;
   ```

2. **Add Bandwidth Throttling**
   - Instead of DROP, delay forwarding of packets for throttled flows.

3. **Add Live Statistics**
   - Periodically print running stats while processing.

4. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet (encrypted differently)

5. **Add Persistent Rules**
   - Save rules to a JSON file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Load-Balanced Architecture** - Routing flows via consistent hashing
5. **Producer-Consumer Pattern** - Reader → LBs → FPs → Output

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

The code is well-commented and follows the same flow described in this document. Start with the simple version (`js/dpiSimple.js`) to understand the concepts, then move to the pipeline engine (`js/dpiMt.js`) to see how the load-balanced architecture is structured. See `js/README.md` for module-level notes.

Happy learning! 🚀
