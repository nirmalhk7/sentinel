import fs from 'fs';
import path from 'path';
import { NmapScanner, NmapHost } from './nmapScanner';
import { DATA_DIR, ensureDataDir } from './paths';

export interface ScanResult {
  id: number;
  category: string;
  feature: string;
  status: 'SAFE' | 'VULNERABLE' | 'WARNING' | 'NEUTRAL';
  description: string;
  finding?: string;
  remediation?: string;
}

export interface NetworkScanRecord {
  target: string;
  scannedAt: string;
  durationMs: number;
  hostCount: number;
  results: ScanResult[];
}

export const DEFAULT_TARGET = process.env.SCAN_TARGET || '192.168.1.0/24';

export function nmapHostsToResults(hosts: NmapHost[]): ScanResult[] {
  const results: ScanResult[] = [];
  for (const host of hosts) {
    for (const p of host.ports) {
      results.push({
        id: 10000 + p.portid,
        category: 'Local Network',
        feature: `Host: ${host.address} | Port: ${p.portid}/${p.protocol}`,
        status: 'NEUTRAL',
        description: `${p.service} ${p.product ?? ''} ${p.version ?? ''} (${p.state})`,
        finding: `Hostnames: ${host.hostnames.join(', ')}`,
        remediation: 'Ensure open ports on local network are necessary and password-protected.',
      });

      if (p.scripts) {
        for (const [sid, output] of Object.entries(p.scripts)) {
          const lower = output.toLowerCase();
          const status: ScanResult['status'] =
            lower.includes('vulnerable') || lower.includes('exploit') ? 'VULNERABLE' : 'WARNING';
          results.push({
            id: 11000 + Math.floor(Math.random() * 9000),
            category: 'Security Script',
            feature: `${sid} on ${host.address}:${p.portid}`,
            status,
            description: output.substring(0, 1000),
            finding: `Nmap script "${sid}" triggered a finding.`,
            remediation: 'Apply relevant security patches and re-evaluate service exposure.',
          });
        }
      }
    }
  }
  return results;
}

class NetworkScanner {
  private historyFile = path.join(DATA_DIR, 'network_scan.json');
  private lastScanTime = 0;
  private scanning = false;

  isRunning(): boolean {
    return this.scanning;
  }

  getLastScanTime(): number {
    return this.lastScanTime;
  }

  getLatest(): NetworkScanRecord | null {
    try {
      if (!fs.existsSync(this.historyFile)) return null;
      const raw = fs.readFileSync(this.historyFile, 'utf8');
      const record = JSON.parse(raw) as NetworkScanRecord;
      if (record?.scannedAt) {
        this.lastScanTime = new Date(record.scannedAt).getTime();
      }
      return record;
    } catch {
      return null;
    }
  }

  saveRecord(record: NetworkScanRecord) {
    ensureDataDir();
    fs.writeFileSync(this.historyFile, JSON.stringify(record, null, 2));
    this.lastScanTime = new Date(record.scannedAt).getTime();
  }

  async runScan(target: string = DEFAULT_TARGET): Promise<NetworkScanRecord | null> {
    if (this.scanning) {
      console.log('[NETWORK SCAN] Skipping — scan already in progress.');
      return null;
    }
    this.scanning = true;
    const start = Date.now();
    console.log(`\x1b[34m[NETWORK SCAN START] Target: ${target}\x1b[0m`);

    try {
      const nmap = new NmapScanner(target);
      const hosts = await nmap.localAudit(true);
      const results = nmapHostsToResults(hosts);
      const record: NetworkScanRecord = {
        target,
        scannedAt: new Date().toISOString(),
        durationMs: Date.now() - start,
        hostCount: hosts.length,
        results,
      };
      this.saveRecord(record);
      console.log(`\x1b[32m[NETWORK SCAN DONE] ${hosts.length} host(s) in ${record.durationMs}ms\x1b[0m`);
      return record;
    } catch (e) {
      const err = e as Error;
      console.error(`\x1b[31m[NETWORK SCAN ERROR] ${err.message}\x1b[0m`);
      return null;
    } finally {
      this.scanning = false;
    }
  }
}

declare global {
  var networkScanner: NetworkScanner | undefined;
}

export const networkScanner = global.networkScanner || new NetworkScanner();
if (process.env.NODE_ENV !== 'production') global.networkScanner = networkScanner;
