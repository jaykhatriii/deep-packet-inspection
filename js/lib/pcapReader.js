'use strict';

// ============================================================================
// pcapReader.js  -  Reads classic (libpcap) .pcap files. The whole file is
// loaded into a Buffer and consumed sequentially.
//
// Endianness: the file's byte order is detected directly from the magic number,
// and every multi-byte field is read with the matching LE/BE accessor.
// ============================================================================

const fs = require('fs');

const PCAP_MAGIC = 0xa1b2c3d4; // microsecond-resolution classic pcap

const GLOBAL_HEADER_LEN = 24;
const PACKET_HEADER_LEN = 16;

class PcapReader {
  constructor() {
    this.buffer = null;
    this.offset = 0;
    this.littleEndian = true;
    this.globalHeader = null;        // parsed fields
    this.globalHeaderBytes = null;   // raw 24 bytes (written verbatim to output)
  }

  // Open a pcap file for reading. Returns true on success.
  open(filename) {
    this.close();

    try {
      this.buffer = fs.readFileSync(filename);
    } catch (err) {
      process.stderr.write(`Error: Could not open file: ${filename}\n`);
      return false;
    }

    if (this.buffer.length < GLOBAL_HEADER_LEN) {
      process.stderr.write('Error: Could not read PCAP global header\n');
      this.close();
      return false;
    }

    // Determine byte order from the magic number.
    const magicLE = this.buffer.readUInt32LE(0);
    const magicBE = this.buffer.readUInt32BE(0);
    if (magicLE === PCAP_MAGIC) {
      this.littleEndian = true;
    } else if (magicBE === PCAP_MAGIC) {
      this.littleEndian = false;
    } else {
      process.stderr.write(
        'Error: Invalid PCAP magic number: 0x' + magicLE.toString(16) + '\n');
      this.close();
      return false;
    }

    const u16 = (o) => this.littleEndian ? this.buffer.readUInt16LE(o) : this.buffer.readUInt16BE(o);
    const u32 = (o) => this.littleEndian ? this.buffer.readUInt32LE(o) : this.buffer.readUInt32BE(o);

    this.globalHeader = {
      magicNumber: u32(0),
      versionMajor: u16(4),
      versionMinor: u16(6),
      thiszone: u32(8) | 0, // signed GMT offset, normally 0
      sigfigs: u32(12),
      snaplen: u32(16),
      network: u32(20),
    };

    // Preserve the original header bytes so the output file reproduces them
    // exactly.
    this.globalHeaderBytes = Buffer.from(this.buffer.subarray(0, GLOBAL_HEADER_LEN));
    this.offset = GLOBAL_HEADER_LEN;

    process.stdout.write(`Opened PCAP file: ${filename}\n`);
    process.stdout.write(`  Version: ${this.globalHeader.versionMajor}.${this.globalHeader.versionMinor}\n`);
    process.stdout.write(`  Snaplen: ${this.globalHeader.snaplen} bytes\n`);
    process.stdout.write(`  Link type: ${this.globalHeader.network}` +
      (this.globalHeader.network === 1 ? ' (Ethernet)' : '') + '\n');

    return true;
  }

  close() {
    this.buffer = null;
    this.offset = 0;
    this.globalHeader = null;
    this.globalHeaderBytes = null;
    this.littleEndian = true;
  }

  isOpen() {
    return this.buffer !== null;
  }

  getGlobalHeader() {
    return this.globalHeader;
  }

  // Read the next packet. Returns a { header, data } object, or null when there
  // are no more packets (end of file) or on a malformed record.
  //   header = { tsSec, tsUsec, inclLen, origLen }
  //   data   = Buffer (the captured packet bytes)
  readNextPacket() {
    if (!this.isOpen()) return null;

    // Need a full 16-byte packet header.
    if (this.offset + PACKET_HEADER_LEN > this.buffer.length) {
      return null;
    }

    const u32 = (o) => this.littleEndian ? this.buffer.readUInt32LE(o) : this.buffer.readUInt32BE(o);

    const header = {
      tsSec: u32(this.offset),
      tsUsec: u32(this.offset + 4),
      inclLen: u32(this.offset + 8),
      origLen: u32(this.offset + 12),
    };
    this.offset += PACKET_HEADER_LEN;

    // Sanity check on packet length.
    if (header.inclLen > this.globalHeader.snaplen || header.inclLen > 65535) {
      process.stderr.write(`Error: Invalid packet length: ${header.inclLen}\n`);
      return null;
    }

    if (this.offset + header.inclLen > this.buffer.length) {
      process.stderr.write('Error: Could not read packet data\n');
      return null;
    }

    const data = Buffer.from(this.buffer.subarray(this.offset, this.offset + header.inclLen));
    this.offset += header.inclLen;

    return { header, data };
  }
}

module.exports = { PcapReader, GLOBAL_HEADER_LEN, PACKET_HEADER_LEN, PCAP_MAGIC };
