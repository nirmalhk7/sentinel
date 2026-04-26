/**
 * /api/local  — Local Network SSE Scan (Internal Audit)
 *
 * POST { network }  (e.g., "192.168.1.0/24")
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { NmapScanner } from '@/utils/nmapScanner';
import { networkScanner, nmapHostsToResults, NetworkScanRecord, ScanResult } from '@/utils/networkScanner';
import { saveSnapshot, loadPrevious } from '@/utils/snapshots';
import { diffById, summarise } from '@/utils/diffEngine';

export const config = { api: { responseLimit: false } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { network } = req.body ?? {};
  const target = network || '127.0.0.1';

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (data: { type: string; payload?: unknown; message?: string; current?: number; total?: number; diff?: unknown }) => {
    if (data.type === 'progress') {
      console.log(`\x1b[35m[LOCAL SCAN] ${data.message}\x1b[0m`);
    } else if (data.type === 'result') {
      const payload = data.payload as { feature: string; category: string; status: string };
      const { feature, category, status } = payload;
      const color = status === 'VULNERABLE' ? '\x1b[31m' : status === 'WARNING' ? '\x1b[33m' : '\x1b[32m';
      console.log(`  └─ [${color}${status}\x1b[0m] ${category}: ${feature}`);
    }
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  console.log(`\x1b[34m[LOCAL SCAN START] Network: ${target}\x1b[0m`);
  send({ type: 'progress', message: `Starting aggressive local audit: ${target}...`, current: 0, total: 1 });

  const nmap = new NmapScanner(target);
  const start = Date.now();

  try {
    const hosts = await nmap.localAudit();
    const results: ScanResult[] = nmapHostsToResults(hosts);

    for (const r of results) {
      send({ type: 'result', payload: r });
    }

    const record: NetworkScanRecord = {
      target,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
      hostCount: hosts.length,
      results,
    };
    networkScanner.saveRecord(record);

    const previous = loadPrevious<ScanResult[]>('network', target);
    saveSnapshot('network', target, results);
    const diff = summarise(diffById(previous?.payload, results, x => `${x.id}-${x.feature}`, x => `${x.status}-${x.description}`));

    send({ type: 'done', message: `Local scan finished. Analyzed ${hosts.length} active host(s).`, diff });
  } catch (e: unknown) {
    const error = e as Error;
    console.error(`\x1b[31m[LOCAL SCAN ERROR] ${error.message}\x1b[0m`);
    send({ type: 'error', message: error.message });
  }

  res.end();
}
