/**
 * Passive local-network monitor.
 *
 * Combines three keyless techniques that never send a probe to the targets:
 *   1. ARP table snapshots — `ip neigh show` (Linux) or `arp -a`. The kernel
 *      already populates this from broadcast traffic the host happens to see.
 *   2. mDNS listener — passively joins 224.0.0.251:5353 and parses replies
 *      that any host on the LAN voluntarily multicasts (printers, AirPlay,
 *      Chromecast, smart-home).
 *   3. SSDP/UPnP listener — passively joins 239.255.255.250:1900 and reads
 *      NOTIFY announcements (routers, IoT, media servers).
 *
 * Devices and announcements are persisted to /data/passive_network.json with
 * first-seen / last-seen timestamps. Educational use only.
 */
import fs from 'fs';
import path from 'path';
import dgram from 'dgram';
import { exec } from 'child_process';
import { promisify } from 'util';
import { DATA_DIR, ensureDataDir } from './paths';

const execAsync = promisify(exec);

export interface PassiveDevice {
  identifier: string; // mac, ip, or USN
  ip?: string;
  mac?: string;
  hostname?: string;
  source: 'arp' | 'mdns' | 'ssdp';
  service?: string;
  meta?: string;
  firstSeen: string;
  lastSeen: string;
}

const STORE = path.join(DATA_DIR, 'passive_network.json');

class PassiveNetworkMonitor {
  private devices = new Map<string, PassiveDevice>();
  private mdnsSocket: dgram.Socket | null = null;
  private ssdpSocket: dgram.Socket | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private running = false;

  constructor() {
    this.load();
  }

  private load() {
    if (!fs.existsSync(STORE)) return;
    try {
      const arr = JSON.parse(fs.readFileSync(STORE, 'utf8')) as PassiveDevice[];
      for (const d of arr) this.devices.set(d.identifier, d);
    } catch {}
  }

  private persist() {
    ensureDataDir();
    fs.writeFileSync(STORE, JSON.stringify(Array.from(this.devices.values()), null, 2));
  }

  private upsert(dev: Omit<PassiveDevice, 'firstSeen' | 'lastSeen'>) {
    const now = new Date().toISOString();
    const existing = this.devices.get(dev.identifier);
    if (existing) {
      existing.lastSeen = now;
      // backfill better metadata
      if (dev.hostname && !existing.hostname) existing.hostname = dev.hostname;
      if (dev.ip && !existing.ip) existing.ip = dev.ip;
      if (dev.mac && !existing.mac) existing.mac = dev.mac;
      if (dev.service && !existing.service) existing.service = dev.service;
      if (dev.meta && !existing.meta) existing.meta = dev.meta;
    } else {
      this.devices.set(dev.identifier, {
        ...dev,
        firstSeen: now,
        lastSeen: now,
      });
    }
    this.persist();
  }

  list(): PassiveDevice[] {
    return Array.from(this.devices.values()).sort((a, b) =>
      new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime(),
    );
  }

  isRunning(): boolean {
    return this.running;
  }

  // ── ARP polling ────────────────────────────────────────────────────
  private async pollArp() {
    let raw = '';
    try {
      const r = await execAsync('ip neigh show 2>/dev/null || arp -a');
      raw = r.stdout || '';
    } catch {
      // tools missing — silent
      return;
    }
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // `ip neigh` format:  192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
      const ipNeigh = trimmed.match(/^([0-9a-fA-F.:]+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})/i);
      if (ipNeigh) {
        const [, ip, , mac] = ipNeigh;
        this.upsert({ identifier: mac.toLowerCase(), ip, mac: mac.toLowerCase(), source: 'arp', meta: 'ARP table' });
        continue;
      }
      // `arp -a` format:  ? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
      const arpA = trimmed.match(/\(([\d.]+)\) at ([0-9a-f:]{17})/i);
      if (arpA) {
        const [, ip, mac] = arpA;
        this.upsert({ identifier: mac.toLowerCase(), ip, mac: mac.toLowerCase(), source: 'arp', meta: 'ARP table' });
      }
    }
  }

  // ── mDNS listener ─────────────────────────────────────────────────
  private startMdns() {
    try {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      sock.on('message', (msg, rinfo) => {
        // We just record presence — full DNS-SD parsing is heavy; the source IP
        // alone is the educational signal that the host advertises a service.
        const ascii = msg.toString('binary');
        const hint = extractMdnsName(ascii);
        this.upsert({
          identifier: `mdns:${rinfo.address}`,
          ip: rinfo.address,
          source: 'mdns',
          service: hint || 'mDNS announce',
        });
      });
      sock.on('error', () => sock.close());
      sock.bind(5353, () => {
        try {
          sock.addMembership('224.0.0.251');
        } catch {}
      });
      this.mdnsSocket = sock;
    } catch {
      // socket bind may fail in restricted envs; fail silently
    }
  }

  // ── SSDP listener ─────────────────────────────────────────────────
  private startSsdp() {
    try {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      sock.on('message', (msg, rinfo) => {
        const text = msg.toString('utf8');
        const usn = /USN:\s*([^\r\n]+)/i.exec(text)?.[1];
        const server = /SERVER:\s*([^\r\n]+)/i.exec(text)?.[1];
        const nt = /NT:\s*([^\r\n]+)/i.exec(text)?.[1];
        this.upsert({
          identifier: usn ? `ssdp:${usn.trim()}` : `ssdp:${rinfo.address}`,
          ip: rinfo.address,
          source: 'ssdp',
          service: nt?.trim() || 'SSDP/UPnP',
          meta: server?.trim(),
        });
      });
      sock.on('error', () => sock.close());
      sock.bind(1900, () => {
        try {
          sock.addMembership('239.255.255.250');
        } catch {}
      });
      this.ssdpSocket = sock;
    } catch {}
  }

  start() {
    if (this.running) return;
    this.running = true;
    console.log('[PASSIVE NET] Starting ARP poll + mDNS/SSDP listeners');
    this.pollArp();
    this.pollTimer = setInterval(() => this.pollArp(), 60_000);
    this.startMdns();
    this.startSsdp();
  }

  stop() {
    if (!this.running) return;
    this.running = false;
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
    if (this.mdnsSocket) {
      try { this.mdnsSocket.close(); } catch {}
      this.mdnsSocket = null;
    }
    if (this.ssdpSocket) {
      try { this.ssdpSocket.close(); } catch {}
      this.ssdpSocket = null;
    }
  }
}

function extractMdnsName(binary: string): string | undefined {
  // Pull printable ASCII runs that look like service / host names.
  const matches = binary.match(/[a-zA-Z0-9_\-.]{4,}\.local/);
  return matches?.[0];
}

declare global {
  var passiveMonitor: PassiveNetworkMonitor | undefined;
}

export const passiveMonitor = global.passiveMonitor || new PassiveNetworkMonitor();
if (process.env.NODE_ENV !== 'production') global.passiveMonitor = passiveMonitor;
