/**
 * /api/scan/stream  — Server-Sent Events endpoint
 *
 * POST { domain, maxPages? }
 * Streams each ScanResult as it is produced so the client renders findings live.
 *
 * Event shapes:
 *   { type: 'progress', message: string }
 *   { type: 'result',   payload: ScanResult }
 *   { type: 'done',     message: string }
 *   { type: 'error',    message: string }
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { VulnerabilityScanner } from '@/utils/vulnerabilityScanner';
import axios from 'axios';

export const config = { api: { responseLimit: false } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { domain, maxPages } = req.body ?? {};
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain required' });

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (data: any) => {
    // Log results and progress to server CLI for developer visibility
    if (data.type === 'progress') {
      console.log(`[SCAN PROGRESS] ${data.message}`);
    } else if (data.type === 'result') {
      const { feature, category, status } = data.payload;
      const statusColor = status === 'VULNERABLE' ? '\x1b[31m' : (status === 'WARNING' ? '\x1b[33m' : '\x1b[32m');
      console.log(`[RESULT] ${category} > ${feature}: ${statusColor}${status}\x1b[0m`);
    } else if (data.type === 'done') {
      console.log(`\x1b[32m[SCAN COMPLETE] ${data.message}\x1b[0m`);
    } else if (data.type === 'error') {
      console.error(`\x1b[31m[SCAN ERROR] ${data.message}\x1b[0m`);
    }

    res.write(`data: ${JSON.stringify(data)}\n\n`);
    if (typeof (res as any).flush === 'function') (res as any).flush();
  };

  const progress = (message: string, current?: number, total?: number) => 
    send({ type: 'progress', message, current, total });

  console.log(`\x1b[34m[SCAN START] Initiating security audit for: ${domain}\x1b[0m`);
  const scanner = new VulnerabilityScanner(
    domain,
    result => send({ type: 'result', payload: result }),
    { maxPages: typeof maxPages === 'number' ? maxPages : 25 },
  );

  try {
    const result = await scanner.runFullScan((msg, cur, tot) => progress(msg, cur, tot));
    if ('error' in result) {
      send({ type: 'error', message: result.error });
    } else {
      send({ 
        type: 'done', 
        message: `Scan complete — ${scanner.discoveredPages.size} page(s), ${scanner.jsResources.size} JS file(s) analysed.`,
        crawlTree: Object.fromEntries(scanner.crawlTree)
      });
    }
  } catch (e: any) {
    send({ type: 'error', message: e.message ?? 'Unknown error during scan' });
  }

  res.end();
}
