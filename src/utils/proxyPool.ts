/**
 * Shared proxy pool — fetched lazily from public proxy lists, refreshed every
 * REFRESH_MS, used by GitHub and OSINT scanners to rotate origin IPs.
 *
 * Educational only.
 */
import axios from 'axios';

interface Proxy {
  host: string;
  port: number;
}

const PROXY_SOURCES = [
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
];
const REFRESH_MS = 30 * 60 * 1000; // 30 min

class ProxyPool {
  private proxies: Proxy[] = [];
  private lastRefresh = 0;
  private refreshing: Promise<void> | null = null;

  size(): number {
    return this.proxies.length;
  }

  lastRefreshedAt(): number {
    return this.lastRefresh;
  }

  async ensureLoaded(): Promise<void> {
    const stale = Date.now() - this.lastRefresh > REFRESH_MS;
    if (this.proxies.length > 0 && !stale) return;
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.refresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refresh(): Promise<void> {
    const found: Proxy[] = [];
    for (const src of PROXY_SOURCES) {
      try {
        const res = await axios.get(src, { timeout: 10000 });
        if (typeof res.data === 'string') {
          for (const line of res.data.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const [host, portStr] = trimmed.split(':');
            const port = parseInt(portStr, 10);
            if (host && Number.isFinite(port)) found.push({ host, port });
          }
        }
      } catch {
        // ignore individual source failures
      }
    }
    if (found.length > 0) {
      this.proxies = found;
      this.lastRefresh = Date.now();
      console.log(`[PROXY POOL] Loaded ${found.length} proxies`);
    } else if (this.proxies.length === 0) {
      console.log('[PROXY POOL] No proxies available — falling back to direct connection');
      this.lastRefresh = Date.now();
    }
  }

  pick(): Proxy | null {
    if (this.proxies.length === 0) return null;
    return this.proxies[Math.floor(Math.random() * this.proxies.length)];
  }
}

declare global {
  var proxyPool: ProxyPool | undefined;
}

export const proxyPool = global.proxyPool || new ProxyPool();
if (process.env.NODE_ENV !== 'production') global.proxyPool = proxyPool;
