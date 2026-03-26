/**
 * /api/scan/[check]
 *
 * Individual REST endpoint per scanner module.
 * POST { domain }  →  runs one check, returns JSON results.
 *
 * Valid [check] values:
 *   fingerprint | headers | passive-headers | cookies | caching |
 *   ssl | dns | whois | policy | methods | crawl | js
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { VulnerabilityScanner, ScanResult } from '@/utils/vulnerabilityScanner';
import axios from 'axios';

const ALLOWED = [
  'fingerprint', 'headers', 'passive-headers', 'cookies', 'caching',
  'ssl', 'dns', 'whois', 'policy', 'methods', 'crawl', 'js',
  'waf', 'ports', 'osint', 'cloud', 'buckets', 'fuzz', 'sca', 'mobile', 'ratelimit', 'topology', 'dynamic'
] as const;
type Check = typeof ALLOWED[number];

async function fetchInitial(scanner: VulnerabilityScanner) {
  return axios.get(scanner.url, {
    validateStatus: () => true, maxRedirects: 5, timeout: 10000,
    headers: { 'User-Agent': 'Mozilla/5.0 SecurityAuditor/2.0' },
  }).catch(() => null);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain required' });

  const check = req.query.check as string;
  if (!ALLOWED.includes(check as Check)) {
    return res.status(400).json({ error: `Invalid check. Choose from: ${ALLOWED.join(', ')}` });
  }

  const collected: ScanResult[] = [];
  const scanner = new VulnerabilityScanner(domain, r => collected.push(r));

  try {
    const needsHttp: Check[] = ['fingerprint', 'headers', 'passive-headers', 'cookies', 'caching', 'waf'];
    let initialRes: any = null;
    if (needsHttp.includes(check as Check)) {
      initialRes = await fetchInitial(scanner);
      if (!initialRes) return res.status(502).json({ error: `Cannot reach ${domain}` });
    }

    switch (check as Check) {
      case 'fingerprint':      await scanner.checkSoftwareFingerprint(initialRes); break;
      case 'headers':          await scanner.checkSecurityHeaders(initialRes); break;
      case 'passive-headers':  await scanner.checkPassiveHeaders(initialRes); break;
      case 'cookies':          await scanner.checkCookieSecurity(initialRes); break;
      case 'caching':          await scanner.checkCachingHeaders(initialRes); break;
      case 'ssl':              await scanner.checkSSL(); break;
      case 'dns':              await scanner.checkDNS(); break;
      case 'whois':            await scanner.checkWhois(); break;
      case 'policy':           await scanner.checkPolicyFiles(); break;
      case 'methods':          await scanner.checkHttpMethods(); break;
      case 'crawl':            await scanner.crawlAndAnalyze(); break;
      case 'js':
        await scanner.crawlAndAnalyze(); 
        await scanner.analyzeJsResources(); break;
      case 'waf':              await scanner.checkWAF(initialRes); break;
      case 'ports':            await scanner.checkPorts(); break;
      case 'osint':            await scanner.subdomainDiscoveryOSINT(); break;
      case 'cloud':            await scanner.checkCloudMetadata(); break;
      case 'buckets':          await scanner.checkCloudBuckets(); break;
      case 'fuzz':             await scanner.performFuzzing(); break;
      case 'sca':              await scanner.checkSCA(); break;
      case 'mobile':           await scanner.checkMobileAssociations(); break;
      case 'ratelimit':        await scanner.checkRateLimiting(scanner.url); break;
      case 'topology':         await scanner.checkTraceroute(); break;
      case 'dynamic':          await scanner.checkDynamicAnalysis(); break;
    }

    return res.status(200).json({
      target: domain, check,
      timestamp: new Date().toISOString(),
      count: collected.length,
      results: collected,
    });
  } catch (e: any) {
    return res.status(500).json({ error: e.message ?? 'Scan failed' });
  }
}
