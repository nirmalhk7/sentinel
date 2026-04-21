/**
 * /api/scan-vulnerabilities  (kept for backwards-compat / batch calls)
 * Runs the full scan synchronously and returns all results in one JSON object.
 * For real-time streaming use /api/scan/stream instead.
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { SecurityScanner, ScanResult } from '@/utils/securityScanner';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { domain } = req.body;
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain required' });

  const collected: ScanResult[] = [];
  const scanner = new SecurityScanner(domain, r => collected.push(r), { maxPages: 25 });

  try {
    const result = await scanner.runFullScan();
    if (result && 'error' in result) {
      return res.status(502).json({ error: result.error });
    }

    const sorted = collected.slice().sort((a, b) => a.id - b.id);
    return res.status(200).json({
      target: domain,
      scanTime: new Date().toISOString(),
      findingsCount: sorted.length,
      vulnerabilities: sorted,
      crawlTree: Object.fromEntries(scanner.crawlTree),
    });
  } catch (e: unknown) {
    const error = e as Error;
    return res.status(500).json({ error: error.message ?? 'Scan failed' });
  }
}
