/**
 * Passive OSINT — queries third-party intelligence APIs without touching the
 * target itself. Each provider degrades gracefully if its API key is missing.
 *
 * Educational use. Findings are emitted as ScanResult-shaped objects so they
 * slot into the existing /api/scan/stream pipeline alongside the active checks.
 */
import axios from 'axios';
import { promises as dns } from 'dns';
import { proxyPool } from './proxyPool';

export interface OsintFinding {
  id: number;
  category: string;
  feature: string;
  status: 'SAFE' | 'VULNERABLE' | 'WARNING' | 'NEUTRAL';
  description: string;
  finding?: string;
  remediation?: string;
}

interface ProviderCtx {
  domain: string;
  ip?: string;
  emit: (f: OsintFinding) => void;
  nextId: () => number;
}

type Provider = {
  name: string;
  enabled: () => boolean;
  enabledHint: string;
  run: (ctx: ProviderCtx) => Promise<void>;
};

const TIMEOUT = 12000;

async function resolveIp(domain: string): Promise<string | undefined> {
  try {
    const records = await dns.resolve4(domain);
    return records[0];
  } catch {
    return undefined;
  }
}

async function getJson<T = unknown>(
  url: string,
  opts: { headers?: Record<string, string>; useProxy?: boolean } = {},
): Promise<T> {
  const config: import('axios').AxiosRequestConfig = {
    headers: { 'User-Agent': 'SENTINEL-OSINT/1.0', ...(opts.headers ?? {}) },
    timeout: TIMEOUT,
  };
  if (opts.useProxy) {
    await proxyPool.ensureLoaded();
    const p = proxyPool.pick();
    if (p) config.proxy = p;
  }
  const res = await axios.get<T>(url, config);
  return res.data;
}

const PROVIDERS: Provider[] = [
  // ── Wayback Machine ─────────────────────────────────────────────────
  {
    name: 'Wayback Machine',
    enabled: () => true,
    enabledHint: '',
    async run({ domain, emit, nextId }) {
      try {
        const data = await getJson<{ archived_snapshots?: { closest?: { url: string; timestamp: string; available: boolean } } }>(
          `https://archive.org/wayback/available?url=${encodeURIComponent(domain)}`,
          { useProxy: true },
        );
        const closest = data?.archived_snapshots?.closest;
        if (closest?.available) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: 'Wayback Machine snapshot',
            status: 'NEUTRAL',
            description: `Archived at ${closest.timestamp}`,
            finding: closest.url,
            remediation: 'Review archived snapshots for accidentally exposed historical content.',
          });
        }

        // CDX: count of historical snapshots
        const cdx = await getJson<unknown[]>(
          `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&limit=1&showNumPages=true`,
          { useProxy: true },
        );
        if (Array.isArray(cdx) && cdx.length > 0) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: 'Wayback CDX index',
            status: 'NEUTRAL',
            description: `Domain has historical archive coverage`,
            finding: `Index pages reported: ${JSON.stringify(cdx[0])}`,
          });
        }
      } catch {
        // silent — provider is best-effort
      }
    },
  },

  // ── BGPView (ASN / ownership) ───────────────────────────────────────
  {
    name: 'BGPView',
    enabled: () => true,
    enabledHint: '',
    async run({ ip, emit, nextId }) {
      if (!ip) return;
      try {
        const data = await getJson<{ data?: { prefixes?: Array<{ prefix: string; name?: string; description?: string; asn?: { asn: number; name: string; description: string; country_code: string } }> } }>(
          `https://api.bgpview.io/ip/${ip}`,
        );
        const prefixes = data?.data?.prefixes ?? [];
        for (const p of prefixes.slice(0, 3)) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: `ASN ownership: ${p.asn?.name ?? 'unknown'}`,
            status: 'NEUTRAL',
            description: `${p.prefix} → AS${p.asn?.asn ?? '?'} (${p.asn?.country_code ?? '?'})`,
            finding: p.asn?.description ?? p.description,
          });
        }
      } catch {
        // silent
      }
    },
  },

  // ── GreyNoise Community ─────────────────────────────────────────────
  {
    name: 'GreyNoise',
    enabled: () => true, // community endpoint is keyless
    enabledHint: 'Set GREYNOISE_API_KEY for richer context queries (community tier works keyless).',
    async run({ ip, emit, nextId }) {
      if (!ip) return;
      try {
        const headers: Record<string, string> = {};
        if (process.env.GREYNOISE_API_KEY) headers['key'] = process.env.GREYNOISE_API_KEY;
        const data = await getJson<{ noise?: boolean; riot?: boolean; classification?: string; name?: string; link?: string; message?: string }>(
          `https://api.greynoise.io/v3/community/${ip}`,
          { headers },
        );
        if (data?.message && /not found/i.test(data.message)) return;
        const status: OsintFinding['status'] = data.classification === 'malicious' ? 'VULNERABLE' : (data.noise || data.riot ? 'WARNING' : 'NEUTRAL');
        emit({
          id: nextId(),
          category: 'Passive Intelligence',
          feature: `GreyNoise: ${data.classification ?? 'unknown'}`,
          status,
          description: `noise=${data.noise} riot=${data.riot} ${data.name ?? ''}`,
          finding: data.link,
        });
      } catch {
        // silent
      }
    },
  },

  // ── URLScan.io passive search ──────────────────────────────────────
  {
    name: 'URLScan.io',
    enabled: () => true, // public search is keyless (rate-limited)
    enabledHint: 'Set URLSCAN_API_KEY to lift the public rate limit.',
    async run({ domain, emit, nextId }) {
      try {
        const headers: Record<string, string> = {};
        if (process.env.URLSCAN_API_KEY) headers['API-Key'] = process.env.URLSCAN_API_KEY;
        const data = await getJson<{ results?: Array<{ task: { url: string; time: string }; page?: { url?: string; ip?: string } }>; total?: number }>(
          `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`,
          { headers },
        );
        if ((data?.total ?? 0) === 0) return;
        emit({
          id: nextId(),
          category: 'Passive Intelligence',
          feature: 'URLScan.io history',
          status: 'NEUTRAL',
          description: `${data.total} prior public scans of this domain`,
          finding: data.results?.[0]?.task?.url,
          remediation: 'Public urlscan submissions can leak sensitive URLs — review and request unlisting if needed.',
        });
      } catch {
        // silent
      }
    },
  },

  // ── Shodan (host) ───────────────────────────────────────────────────
  {
    name: 'Shodan',
    enabled: () => !!process.env.SHODAN_API_KEY,
    enabledHint: 'Set SHODAN_API_KEY to enable indexed-banner lookups.',
    async run({ ip, emit, nextId }) {
      if (!ip) return;
      try {
        const data = await getJson<{ ports?: number[]; org?: string; os?: string; vulns?: string[]; data?: Array<{ port: number; product?: string; version?: string }> }>(
          `https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`,
        );
        if (data?.ports?.length) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: `Shodan: indexed open ports`,
            status: 'WARNING',
            description: `${data.ports.length} port(s): ${data.ports.slice(0, 20).join(', ')}`,
            finding: `Org: ${data.org ?? '—'}, OS: ${data.os ?? '—'}`,
            remediation: 'These ports were indexed without us probing — they are publicly visible.',
          });
        }
        if (data?.vulns?.length) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: `Shodan: known CVEs`,
            status: 'VULNERABLE',
            description: `${data.vulns.length} CVE(s) referenced for this host`,
            finding: data.vulns.slice(0, 10).join(', '),
            remediation: 'Patch services or restrict exposure.',
          });
        }
      } catch {
        // silent
      }
    },
  },

  // ── Censys ──────────────────────────────────────────────────────────
  {
    name: 'Censys',
    enabled: () => !!(process.env.CENSYS_API_ID && process.env.CENSYS_API_SECRET),
    enabledHint: 'Set CENSYS_API_ID and CENSYS_API_SECRET to enable.',
    async run({ ip, emit, nextId }) {
      if (!ip) return;
      try {
        const auth = Buffer.from(`${process.env.CENSYS_API_ID}:${process.env.CENSYS_API_SECRET}`).toString('base64');
        const data = await getJson<{ result?: { services?: Array<{ port: number; service_name?: string; transport_protocol?: string }> } }>(
          `https://search.censys.io/api/v2/hosts/${ip}`,
          { headers: { Authorization: `Basic ${auth}` } },
        );
        const services = data?.result?.services ?? [];
        if (services.length > 0) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: 'Censys: indexed services',
            status: 'WARNING',
            description: `${services.length} service(s) indexed`,
            finding: services.slice(0, 8).map(s => `${s.port}/${s.transport_protocol ?? 'tcp'} ${s.service_name ?? ''}`).join(' | '),
          });
        }
      } catch {
        // silent
      }
    },
  },

  // ── VirusTotal ──────────────────────────────────────────────────────
  {
    name: 'VirusTotal',
    enabled: () => !!process.env.VT_API_KEY,
    enabledHint: 'Set VT_API_KEY to enable reputation, passive DNS, and sibling lookups.',
    async run({ domain, emit, nextId }) {
      try {
        const data = await getJson<{ data?: { attributes?: { last_analysis_stats?: { malicious: number; suspicious: number; harmless: number }; reputation?: number; categories?: Record<string, string> } } }>(
          `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
          { headers: { 'x-apikey': process.env.VT_API_KEY! } },
        );
        const attr = data?.data?.attributes;
        if (!attr) return;
        const stats = attr.last_analysis_stats;
        const malicious = (stats?.malicious ?? 0) + (stats?.suspicious ?? 0);
        emit({
          id: nextId(),
          category: 'Passive Intelligence',
          feature: 'VirusTotal: reputation',
          status: malicious > 0 ? 'VULNERABLE' : 'NEUTRAL',
          description: `malicious=${stats?.malicious ?? 0} suspicious=${stats?.suspicious ?? 0} harmless=${stats?.harmless ?? 0}`,
          finding: `Reputation score: ${attr.reputation ?? 'n/a'}`,
        });

        // Passive DNS resolutions (siblings)
        try {
          const resos = await getJson<{ data?: Array<{ attributes?: { ip_address: string; date: number } }> }>(
            `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/resolutions?limit=10`,
            { headers: { 'x-apikey': process.env.VT_API_KEY! } },
          );
          const ips = resos?.data?.map(r => r.attributes?.ip_address).filter(Boolean) as string[];
          if (ips?.length) {
            emit({
              id: nextId(),
              category: 'Passive Intelligence',
              feature: 'VirusTotal: passive DNS',
              status: 'NEUTRAL',
              description: `Domain historically resolved to ${ips.length} IP(s)`,
              finding: ips.slice(0, 8).join(', '),
            });
          }
        } catch {}
      } catch {
        // silent
      }
    },
  },

  // ── Have I Been Pwned (domain breaches) ────────────────────────────
  {
    name: 'HIBP',
    enabled: () => !!process.env.HIBP_API_KEY,
    enabledHint: 'Set HIBP_API_KEY to enable domain-level breach exposure.',
    async run({ domain, emit, nextId }) {
      try {
        const data = await getJson<Array<{ Name: string; BreachDate: string; PwnCount: number; DataClasses: string[] }>>(
          `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
          { headers: { 'hibp-api-key': process.env.HIBP_API_KEY!, 'User-Agent': 'SENTINEL-OSINT/1.0' } },
        );
        if (Array.isArray(data) && data.length > 0) {
          for (const breach of data.slice(0, 10)) {
            emit({
              id: nextId(),
              category: 'Passive Intelligence',
              feature: `HIBP: breach "${breach.Name}"`,
              status: 'VULNERABLE',
              description: `${breach.PwnCount} accounts exposed on ${breach.BreachDate}`,
              finding: breach.DataClasses.join(', '),
              remediation: 'Force password resets for affected accounts; enable MFA.',
            });
          }
        }
      } catch {
        // silent
      }
    },
  },

  // ── SecurityTrails passive DNS ─────────────────────────────────────
  {
    name: 'SecurityTrails',
    enabled: () => !!process.env.SECURITYTRAILS_API_KEY,
    enabledHint: 'Set SECURITYTRAILS_API_KEY to enable historical DNS data.',
    async run({ domain, emit, nextId }) {
      try {
        const sub = await getJson<{ subdomains?: string[]; subdomain_count?: number }>(
          `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=false`,
          { headers: { APIKEY: process.env.SECURITYTRAILS_API_KEY! } },
        );
        if (sub?.subdomains?.length) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: 'SecurityTrails: subdomain inventory',
            status: 'NEUTRAL',
            description: `${sub.subdomains.length} subdomain(s) indexed`,
            finding: sub.subdomains.slice(0, 12).map(s => `${s}.${domain}`).join(', '),
          });
        }
      } catch {
        // silent
      }
    },
  },

  // ── Hunter.io email pattern ────────────────────────────────────────
  {
    name: 'Hunter.io',
    enabled: () => !!process.env.HUNTER_API_KEY,
    enabledHint: 'Set HUNTER_API_KEY to enable email pattern discovery.',
    async run({ domain, emit, nextId }) {
      try {
        const data = await getJson<{ data?: { pattern?: string; emails?: Array<{ value: string; type?: string }> } }>(
          `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${process.env.HUNTER_API_KEY}`,
        );
        if (data?.data?.pattern) {
          emit({
            id: nextId(),
            category: 'Passive Intelligence',
            feature: 'Hunter.io: email pattern',
            status: 'WARNING',
            description: `Discovered email pattern: ${data.data.pattern}@${domain}`,
            finding: `${data.data.emails?.length ?? 0} email(s) indexed`,
            remediation: 'Predictable email patterns aid spear-phishing — consider obfuscation or shared aliases.',
          });
        }
      } catch {
        // silent
      }
    },
  },
];

export interface OsintRunOptions {
  emit: (f: OsintFinding) => void;
  startId?: number;
}

export interface OsintProviderHealth {
  name: string;
  enabled: boolean;
  hint: string;
}

export function listProviders(): OsintProviderHealth[] {
  return PROVIDERS.map(p => ({ name: p.name, enabled: p.enabled(), hint: p.enabledHint }));
}

export async function runOsint(domain: string, opts: OsintRunOptions): Promise<OsintFinding[]> {
  const collected: OsintFinding[] = [];
  let id = opts.startId ?? 50000;
  const nextId = () => ++id;

  const ip = await resolveIp(domain);
  if (ip) {
    opts.emit({
      id: nextId(),
      category: 'Passive Intelligence',
      feature: 'DNS A record',
      status: 'NEUTRAL',
      description: `${domain} → ${ip}`,
    });
  }

  const providerPromises = PROVIDERS.map(async (p) => {
    if (!p.enabled()) {
      const finding: OsintFinding = {
        id: nextId(),
        category: 'Passive Intelligence',
        feature: `${p.name}: not configured`,
        status: 'NEUTRAL',
        description: 'Provider disabled — no API key in env.',
        finding: p.enabledHint,
      };
      opts.emit(finding);
      collected.push(finding);
      return;
    }
    const ctx: ProviderCtx = {
      domain,
      ip,
      nextId,
      emit: (f) => {
        opts.emit(f);
        collected.push(f);
      },
    };
    try {
      await p.run(ctx);
    } catch (e) {
      const err = e as Error;
      console.warn(`[OSINT ${p.name}] ${err.message}`);
    }
  });

  await Promise.allSettled(providerPromises);

  return collected;
}
