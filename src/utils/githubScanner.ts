import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { EventEmitter } from 'events';

export interface EnvPair {
  key: string;
  value: string;
}

export interface GitHubEnvResult {
  repository: string;
  url: string;
  contentSnippet: string;
  foundAt: string;
  isLikelySensitive: boolean;
  extractedEnvs: EnvPair[];
}

export class GitHubScanner extends EventEmitter {
  private historyFile = path.join(process.cwd(), '.github_scan_history.json');
  private lastScanTime: number = 0;
  private isScanning: boolean = false;
  private proxies: string[] = [];

  private sensitiveRegex = [
    /API_KEY\s*=\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?/i,
    /SECRET\s*=\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?/i,
    /PASSWORD\s*=\s*['"]?[a-zA-Z0-9_\-]{8,}['"]?/i,
    /DATABASE_URL\s*=\s*['"]?postgres:\/\/.+['"]?/i,
    /DATABASE_URL\s*=\s*['"]?mysql:\/\/.+['"]?/i,
    /DATABASE_URL\s*=\s*['"]?mongodb(?:\+srv)?:\/\/.+['"]?/i,
    /AWS_SECRET_ACCESS_KEY\s*=\s*['"]?[a-zA-Z0-9\/+]{40}['"]?/i,
    /STRIPE_SECRET\s*=\s*['"]?sk_(?:test|live)_[a-zA-Z0-9]{24}['"]?/i,
    /SENDGRID_API_KEY\s*=\s*['"]?SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}['"]?/i,
  ];

  private isMonitoring = false;

  constructor() {
    this.loadProxies();
    this.startBackgroundMonitor();
  }

  private startBackgroundMonitor() {
    if (this.isMonitoring) return;
    this.isMonitoring = true;

    console.log('[GITHUB MONITOR] Starting internal scheduler (30-minute intervals)...');
    
    // Run immediately on creation
    this.runScan();

    // Check every minute if it's time to scan
    setInterval(() => {
      const now = Date.now();
      const thirtyMinutes = 30 * 60 * 1000;
      
      if (now - this.lastScanTime >= thirtyMinutes) {
        console.log('[GITHUB MONITOR] Interval reached. Firing scheduled scan...');
        this.runScan();
      }
    }, 60000);
  }

  private async loadProxies() {
    try {
      const res = await axios.get('https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all');
      if (res.data && typeof res.data === 'string') {
        this.proxies = res.data.split('\n').map(p => p.trim()).filter(p => p);
      }
    } catch (e) {
      console.error('Failed to fetch proxies, using direct connection fallback');
    }
  }

  private getProxy() {
    if (this.proxies.length === 0) return null;
    const proxy = this.proxies[Math.floor(Math.random() * this.proxies.length)];
    const [host, port] = proxy.split(':');
    return { host, port: parseInt(port) };
  }

  private extractEnvs(content: string): EnvPair[] {
    const lines = content.split('\n');
    const envs: EnvPair[] = [];
    // Match KEY=VALUE or KEY = VALUE
    const regex = /^([A-Z0-9_]+)\s*=\s*(.*)$/i;

    lines.forEach(line => {
      const match = line.trim().match(regex);
      if (match) {
        let val = match[2].trim();
        // Remove quotes if present
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.substring(1, val.length - 1);
        }
        if (val && val !== 'your-key-here' && val !== 'placeholder') {
           envs.push({ key: match[1], value: val });
        }
      }
    });
    return envs;
  }

  public async runScan(): Promise<GitHubEnvResult[]> {
    if (this.isScanning) return [];
    this.isScanning = true;
    
    const results: GitHubEnvResult[] = [];
    const queries = [
      'filename:.env',
      'filename:.env.local',
      'filename:.env.production',
    ];

    console.log(`[GITHUB SCAN] Starting automated search...`);

    for (const query of queries) {
      try {
        const proxy = this.getProxy();
        const config: any = {
          params: {
            q: query,
            per_page: 15,
            sort: 'indexed',
            order: 'desc'
          },
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SENTINEL-BOT/1.0'
          },
          timeout: 20000
        };

        if (proxy) {
          config.proxy = proxy;
        }

        const res = await axios.get('https://api.github.com/search/code', config);

        if (res.data && res.data.items) {
          for (const item of res.data.items) {
            // Try to fetch raw content to get ALL env values
            let content = '';
            try {
              // Convert html_url to raw.githubusercontent.com URL
              // Example: https://github.com/owner/repo/blob/branch/path/.env
              // To: https://raw.githubusercontent.com/owner/repo/branch/path/.env
              const rawUrl = item.html_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
              const contentRes = await axios.get(rawUrl, { timeout: 5000 });
              content = contentRes.data;
            } catch (e) {
              // Fallback to snippet if raw fetch fails
              content = item.text_matches?.[0]?.fragment || '';
            }

            const extracted = this.extractEnvs(content);
            const isSensitive = this.sensitiveRegex.some(regex => regex.test(content));
            
            if (extracted.length > 0) {
              const result: GitHubEnvResult = {
                repository: item.repository.full_name,
                url: item.html_url,
                contentSnippet: content.substring(0, 200) + '...',
                foundAt: new Date().toISOString(),
                isLikelySensitive: isSensitive,
                extractedEnvs: extracted
              };
              
              results.push(result);
              this.emit('result', result); // Emit real-time event
              this.saveResults([result]);  // Save incrementally
            }
          }
        }
        
        // Sleep to avoid rate limiting
        await new Promise(r => setTimeout(r, 3000));

      } catch (e: any) {
        console.error(`[GITHUB SCAN ERROR] Query "${query}" failed:`, e.message);
      }
    }

    this.isScanning = false;
    this.lastScanTime = Date.now();
    return results;
  }

  private saveResults(newResults: GitHubEnvResult[]) {
    let existing: GitHubEnvResult[] = [];
    if (fs.existsSync(this.historyFile)) {
      try {
        existing = JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
      } catch {}
    }

    // Filter out duplicates (by URL)
    const all = [...newResults, ...existing];
    const uniqueMap = new Map();
    all.forEach(r => {
      if (!uniqueMap.has(r.url)) {
        uniqueMap.set(r.url, r);
      }
    });
    
    const unique = Array.from(uniqueMap.values());
    
    // Keep only last 200 for size
    const final = unique.slice(0, 200);
    fs.writeFileSync(this.historyFile, JSON.stringify(final, null, 2));
  }

  public getHistory(): GitHubEnvResult[] {
    if (fs.existsSync(this.historyFile)) {
      try {
        return JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
      } catch {}
    }
    return [];
  }

  public getLastScanTime(): number {
    return this.lastScanTime;
  }
}

declare global {
  var githubScanner: GitHubScanner | undefined;
}

export const githubScanner = global.githubScanner || new GitHubScanner();
if (process.env.NODE_ENV !== 'production') global.githubScanner = githubScanner;
