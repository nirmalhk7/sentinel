import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { EventEmitter } from 'events';
import { DATA_DIR, ensureDataDir } from './paths';
import { proxyPool } from './proxyPool';

export interface EnvPair {
  key: string;
  value: string;
}

export interface ExtractedSecret {
  type: string;
  value: string;
}

export interface GitHubEnvResult {
  repository: string;
  url: string;
  contentSnippet: string;
  foundAt: string;
  isLikelySensitive: boolean;
  extractedEnvs: EnvPair[];
  extractedSecrets?: ExtractedSecret[];
  query?: string;
  contentHash?: string;
}

export interface GitHubScanHealth {
  proxyCount: number;
  lastProxyRefresh: number;
  tokenCount: number;
  queryCount: number;
  totalResults: number;
  lastScanTime: number;
  isScanning: boolean;
}

const HISTORY_LIMIT = 1000;
const PER_PAGE = 100;
const MAX_PAGES_PER_QUERY = 10; // GitHub caps search at 1000 results

const SENSITIVE_FILENAME_QUERIES = [
  'filename:.env',
  'filename:.env.local',
  'filename:.env.production',
  'filename:.env.development',
  'filename:.env.staging',
  'filename:credentials',
  'filename:credentials.json',
  'filename:secrets.yml',
  'filename:secrets.yaml',
  'filename:wp-config.php',
  'filename:database.yml password',
  'filename:settings.py SECRET_KEY',
  'filename:config.json password',
  'filename:id_rsa',
  'filename:id_dsa',
  'filename:.npmrc _authToken',
  'filename:.dockercfg auth',
  'filename:.docker/config.json auth',
  'filename:.aws/credentials',
  'filename:firebase-adminsdk',
  'filename:.git-credentials',
  'filename:.netrc password',
  'filename:.s3cfg secret_key',
  'filename:auth.json password',
  'extension:pem private',
];

const SECRET_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: 'AWS Access Key ID', regex: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { type: 'AWS Secret Access Key', regex: /\b[A-Za-z0-9/+]{40}\b(?=.*aws)/gi },
  { type: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { type: 'GitHub PAT', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { type: 'Slack token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'Stripe secret', regex: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/g },
  { type: 'SendGrid', regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { type: 'Mailgun', regex: /\bkey-[a-z0-9]{32}\b/g },
  { type: 'Twilio SID', regex: /\bAC[a-f0-9]{32}\b/g },
  { type: 'Heroku key', regex: /\b[hH]eroku[a-z0-9_]{0,16}\s*[=:]\s*['"]?[a-f0-9]{32}['"]?/g },
  { type: 'JWT', regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  { type: 'Private Key (PEM)', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----/g },
];

const SENSITIVE_HEURISTICS = [
  /API_KEY\s*=\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?/i,
  /SECRET\s*=\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?/i,
  /PASSWORD\s*=\s*['"]?[a-zA-Z0-9_\-]{8,}['"]?/i,
  /DATABASE_URL\s*=\s*['"]?(?:postgres|mysql|mongodb(?:\+srv)?):\/\/.+['"]?/i,
  /AWS_SECRET_ACCESS_KEY\s*=/i,
  /STRIPE_SECRET\s*=/i,
];

export class GitHubScanner extends EventEmitter {
  private historyFile = path.join(DATA_DIR, 'github_scan_history.json');
  private lastScanTime = 0;
  private isScanning = false;
  private tokens: string[] = [];
  private tokenCursor = 0;

  constructor() {
    super();
    this.loadTokens();
  }

  private loadTokens() {
    const single = process.env.GITHUB_TOKEN;
    const many = process.env.GITHUB_TOKENS;
    const set = new Set<string>();
    if (single) set.add(single.trim());
    if (many) many.split(',').map(t => t.trim()).filter(Boolean).forEach(t => set.add(t));
    this.tokens = Array.from(set);
  }

  private nextToken(): string | null {
    if (this.tokens.length === 0) return null;
    const t = this.tokens[this.tokenCursor % this.tokens.length];
    this.tokenCursor++;
    return t;
  }

  private extractEnvs(content: string): EnvPair[] {
    const envs: EnvPair[] = [];
    const regex = /^([A-Z][A-Z0-9_]{1,80})\s*=\s*(.*)$/i;
    for (const raw of content.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const match = line.match(regex);
      if (!match) continue;
      let val = match[2].trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!val || /^(your[-_]?key|placeholder|changeme|xxx+|<.*>)$/i.test(val)) continue;
      envs.push({ key: match[1], value: val });
    }
    return envs;
  }

  private extractSecrets(content: string): ExtractedSecret[] {
    const out: ExtractedSecret[] = [];
    const seen = new Set<string>();
    for (const { type, regex } of SECRET_PATTERNS) {
      const matches = content.match(regex);
      if (!matches) continue;
      for (const m of matches) {
        const key = `${type}:${m}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ type, value: m.length > 200 ? m.slice(0, 200) + '…' : m });
      }
    }
    return out;
  }

  private looksSensitive(content: string, secrets: ExtractedSecret[]): boolean {
    if (secrets.length > 0) return true;
    return SENSITIVE_HEURISTICS.some(rx => rx.test(content));
  }

  private hash(content: string): string {
    return crypto.createHash('sha1').update(content).digest('hex');
  }

  private rawUrl(htmlUrl: string): string {
    return htmlUrl
      .replace('https://github.com', 'https://raw.githubusercontent.com')
      .replace('/blob/', '/');
  }

  private async fetchSearch(query: string, page: number): Promise<{ items: Array<{ html_url: string; repository: { full_name: string }; text_matches?: Array<{ fragment: string }> }>; rateLimited: boolean }> {
    await proxyPool.ensureLoaded();
    const proxy = proxyPool.pick();
    const token = this.nextToken();

    const config: import('axios').AxiosRequestConfig = {
      params: { q: query, per_page: PER_PAGE, page, sort: 'indexed', order: 'desc' },
      headers: {
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'Mozilla/5.0 SENTINEL-BOT/2.0',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      timeout: 25000,
      validateStatus: () => true,
    };
    if (proxy) config.proxy = proxy;

    const res = await axios.get('https://api.github.com/search/code', config);
    if (res.status === 403 || res.status === 429) {
      return { items: [], rateLimited: true };
    }
    if (res.status >= 400) {
      return { items: [], rateLimited: false };
    }
    return { items: res.data?.items ?? [], rateLimited: false };
  }

  private async fetchRaw(htmlUrl: string): Promise<string> {
    try {
      const res = await axios.get(this.rawUrl(htmlUrl), { timeout: 8000, validateStatus: () => true });
      return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    } catch {
      return '';
    }
  }

  public health(): GitHubScanHealth {
    return {
      proxyCount: proxyPool.size(),
      lastProxyRefresh: proxyPool.lastRefreshedAt(),
      tokenCount: this.tokens.length,
      queryCount: SENSITIVE_FILENAME_QUERIES.length,
      totalResults: this.getHistory().length,
      lastScanTime: this.getLastScanTime(),
      isScanning: this.isScanning,
    };
  }

  public async runScan(): Promise<GitHubEnvResult[]> {
    if (this.isScanning) return [];
    this.isScanning = true;
    const collected: GitHubEnvResult[] = [];
    console.log(`[GITHUB SCAN] start — ${SENSITIVE_FILENAME_QUERIES.length} queries × up to ${MAX_PAGES_PER_QUERY} pages × ${PER_PAGE}/page`);

    try {
      for (const query of SENSITIVE_FILENAME_QUERIES) {
        for (let page = 1; page <= MAX_PAGES_PER_QUERY; page++) {
          let res;
          try {
            res = await this.fetchSearch(query, page);
          } catch (e) {
            const err = e as Error;
            console.warn(`[GITHUB SCAN] "${query}" page ${page}: ${err.message}`);
            break;
          }
          if (res.rateLimited) {
            console.warn(`[GITHUB SCAN] rate-limited on "${query}" page ${page} — backing off 30s`);
            await delay(30_000);
            page--; // retry
            continue;
          }
          if (res.items.length === 0) break;

          for (const item of res.items) {
            try {
              const raw = await this.fetchRaw(item.html_url);
              const content = raw || item.text_matches?.[0]?.fragment || '';
              if (!content) continue;

              const envs = this.extractEnvs(content);
              const secrets = this.extractSecrets(content);
              if (envs.length === 0 && secrets.length === 0) continue;

              const sensitive = this.looksSensitive(content, secrets);
              const result: GitHubEnvResult = {
                repository: item.repository.full_name,
                url: item.html_url,
                contentSnippet: content.substring(0, 200) + (content.length > 200 ? '…' : ''),
                foundAt: new Date().toISOString(),
                isLikelySensitive: sensitive,
                extractedEnvs: envs,
                extractedSecrets: secrets,
                query,
                contentHash: this.hash(content),
              };
              collected.push(result);
              this.emit('result', result);
              this.saveResults([result]);
            } catch (e) {
              const err = e as Error;
              console.warn(`[GITHUB SCAN] item failed: ${err.message}`);
            }
          }

          // gentle pacing per page
          await delay(2000);
        }
        // cool down between queries
        await delay(3000);
      }
    } finally {
      this.isScanning = false;
      this.lastScanTime = Date.now();
      console.log(`[GITHUB SCAN] complete — collected ${collected.length} new file(s)`);
    }
    return collected;
  }

  private saveResults(newResults: GitHubEnvResult[]) {
    ensureDataDir();
    let existing: GitHubEnvResult[] = [];
    if (fs.existsSync(this.historyFile)) {
      try {
        existing = JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
      } catch {}
    }
    const all = [...newResults, ...existing];
    const dedup = new Map<string, GitHubEnvResult>();
    for (const r of all) {
      const key = `${r.repository}|${r.url}|${r.contentHash ?? ''}`;
      if (!dedup.has(key)) dedup.set(key, r);
    }
    const final = Array.from(dedup.values()).slice(0, HISTORY_LIMIT);
    fs.writeFileSync(this.historyFile, JSON.stringify(final, null, 2));
  }

  public getHistory(): GitHubEnvResult[] {
    if (!fs.existsSync(this.historyFile)) return [];
    try {
      return JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
    } catch {
      return [];
    }
  }

  public getLastScanTime(): number {
    if (this.lastScanTime > 0) return this.lastScanTime;
    const history = this.getHistory();
    if (history.length > 0) {
      const max = Math.max(...history.map(h => new Date(h.foundAt).getTime()));
      this.lastScanTime = max;
      return max;
    }
    return 0;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

declare global {
  var githubScanner: GitHubScanner | undefined;
}

export const githubScanner = global.githubScanner || new GitHubScanner();
if (process.env.NODE_ENV !== 'production') global.githubScanner = githubScanner;
