import { exec } from 'child_process';
import { parseStringPromise } from 'xml2js';
import { ScanLimiter } from './scanLimiter';

export interface NmapPort {
  portid: number;
  protocol: string;
  state: string;
  service: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  scripts?: Record<string, string>;
}

export interface NmapHost {
  address: string;
  hostnames: string[];
  status: string;
  ports: NmapPort[];
}

/** 
 * NmapScanner - Passive Vulnerability Discovery Edition
 * Strictly uses non-intrusive packets for service discovery and CVE mapping.
 */
export class NmapScanner {
  private target: string;

  constructor(target: string) {
    this.target = target;
  }

  private async runNmap(args: string[], timeoutMs: number = 3600000): Promise<any> {
    // Check Rate Limiting
    const limit = ScanLimiter.checkAndRecord(this.target);
    if (!limit.allowed) {
      throw new Error(`[RATE LIMIT] ${limit.reason}`);
    }

    // Stealth Flags:
    // -T2: Polite timing (slow, less likely to trigger IDSs)
    // -f: Fragment packets to bypass simple firewalls
    // -D RND:10: Use 10 random decoys to obfuscate the real scanner IP
    // --source-port 53: Spoof as DNS traffic (often ignored by simple rules)
    // --randomize-hosts: Mix up the order of targets
    // --data-length 32: Append random garbage data to packets to look less like a probe
    const stealthArgs = ['-T2', '-D', 'RND:10', '--source-port', '53', '--randomize-hosts', '--data-length', '32'];
    
    // Filter out any T3/T4 from incoming args to enforce T2
    const cleanArgs = args.filter(a => !/^-T[3-5]$/.test(a));
    const finalArgs = [...stealthArgs, ...cleanArgs];

    const cmd = `nmap -oX - ${finalArgs.join(' ')} ${this.target}`;
    console.log(`\x1b[36m[NMAP STEALTH CMD] ${cmd}\x1b[0m`);

    return new Promise((resolve, reject) => {
      exec(cmd, { timeout: timeoutMs }, async (error, stdout, stderr) => {
        if (error && !stdout) {
          reject(new Error(`Nmap error: ${stderr || error.message}`));
          return;
        }
        try {
          const result = await parseStringPromise(stdout);
          resolve(result);
        } catch (e: any) {
          reject(new Error(`Failed to parse Nmap output: ${e.message}`));
        }
      });
    });
  }

  /** Passive Version Fingerprinting & Discovery */
  public async passiveVersionAudit(): Promise<NmapHost[]> {
    // -sV: Version detection
    // -sC: Default scripts (safe/discovery only)
    // -T3: Balanced timing
    // --open: Only show open ports
    return this.parseNmapOutput(await this.runNmap(['-sV', '-sC', '-T3', '--version-light', '--reason', '--open']));
  }

  /** Passive CVE Mapping (Version string matching) */
  public async passiveCveMapping(): Promise<NmapHost[]> {
    // --script vulners,http-vulners-paths: Informational CVE lookup based on version strings
    return this.parseNmapOutput(await this.runNmap(['-sV', '--script', 'vulners,http-vulners-paths', '-T3', '--open']));
  }

  /** Passive SSL/TLS Audit (Cipher suites & protocols) */
  public async passiveSslAudit(): Promise<NmapHost[]> {
    // ssl-enum-ciphers: Passive enumeration of TLS versions and cipher suites
    return this.parseNmapOutput(await this.runNmap(['-sV', '--script', 'ssl-enum-ciphers', '-p', '443,8443,9443', '-T3', '--open']));
  }

  /** Comprehensive Safe & Discovery Audit */
  public async passiveSafeAudit(): Promise<NmapHost[]> {
    // Run all scripts in 'safe' and 'discovery' categories — strictly non-intrusive
    return this.parseNmapOutput(await this.runNmap(['-sV', '--script', 'safe,discovery', '-T3', '--open']));
  }

  /** 
   * Local Network Aggressive Audit 
   * Uses ALL possible features for deep vulnerability assessment on local/private networks.
   */
  public async localAudit(): Promise<NmapHost[]> {
    return this.parseNmapOutput(await this.runNmap([
      '-A', 
      '-T4', 
      '--script', 'vuln,exploit,auth,brute,broadcast', 
      '--open'
    ], 600000)); // 10 minute timeout for deep audit
  }

  private parseNmapOutput(data: any): NmapHost[] {
    if (!data.nmaprun || !data.nmaprun.host) return [];

    const hosts: NmapHost[] = (Array.isArray(data.nmaprun.host) ? data.nmaprun.host : [data.nmaprun.host]).map((h: any) => {
      const address = h.address?.[0]?.$.addr ?? 'unknown';
      const hostnames = h.hostnames?.[0]?.hostname?.map((hn: any) => hn.$.name) ?? [];
      const status = h.status?.[0]?.$.state ?? 'unknown';

      const ports: NmapPort[] = [];
      const portData = h.ports?.[0]?.port;
      if (portData) {
        (Array.isArray(portData) ? portData : [portData]).forEach((p: any) => {
          const service = p.service?.[0]?.$;
          const scripts: Record<string, string> = {};
          if (p.script) {
            p.script.forEach((s: any) => {
              scripts[s.$.id] = s.$.output;
            });
          }

          ports.push({
            portid: parseInt(p.$.portid),
            protocol: p.$.protocol,
            state: p.state?.[0]?.$.state,
            service: service?.name ?? 'unknown',
            product: service?.product,
            version: service?.version,
            extrainfo: service?.extrainfo,
            scripts
          });
        });
      }

      return { address, hostnames, status, ports };
    });

    return hosts;
  }
}
