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
import { SecurityScanner } from '@/utils/securityScanner';
import { saveSnapshot, loadPrevious } from '@/utils/snapshots';
import { diffById, summarise } from '@/utils/diffEngine';
import { runOsint } from '@/utils/osintScanner';

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

  const send = (data: { type: string; payload?: unknown; message?: string; current?: number; total?: number; crawlTree?: unknown; diff?: unknown }) => {
    // Log results and progress to server CLI for developer visibility
    if (data.type === 'progress') {
      console.log(`[SCAN PROGRESS] ${data.message}`);
    } else if (data.type === 'result') {
      const payload = data.payload as import('@/utils/securityScanner').ScanResult;
      const { feature, category, status } = payload;
      const statusColor = status === 'VULNERABLE' ? '\x1b[31m' : (status === 'WARNING' ? '\x1b[33m' : '\x1b[32m');
      console.log(`[RESULT] ${category} > ${feature}: ${statusColor}${status}\x1b[0m`);
    } else if (data.type === 'done') {
      console.log(`\x1b[32m[SCAN COMPLETE] ${data.message}\x1b[0m`);
    } else if (data.type === 'error') {
      console.error(`\x1b[31m[SCAN ERROR] ${data.message}\x1b[0m`);
    }

    res.write(`data: ${JSON.stringify(data)}\n\n`);
    if (typeof (res as unknown as { flush: () => void }).flush === 'function') (res as unknown as { flush: () => void }).flush();
  };

  const progress = (message: string, current?: number, total?: number) => 
    send({ type: 'progress', message, current, total });

  console.log(`\x1b[34m[SCAN START] Initiating security audit for: ${domain}\x1b[0m`);
  const collected: import('@/utils/securityScanner').ScanResult[] = [];
  const scanner = new SecurityScanner(
    domain,
    result => {
      collected.push(result);
      send({ type: 'result', payload: result });
    },
    { maxPages: typeof maxPages === 'number' ? maxPages : 25 },
  );

  try {
    const result = await scanner.runFullScan((msg, cur, tot) => progress(msg, cur, tot));
    if ('error' in result) {
      send({ type: 'error', message: result.error });
    } else {
      // Layer in passive OSINT findings on the same stream
      progress('Running passive OSINT lookups…');
      try {
        await runOsint(domain, {
          emit: f => {
            collected.push(f as unknown as import('@/utils/securityScanner').ScanResult);
            send({ type: 'result', payload: f });
          },
        });
      } catch (e) {
        const err = e as Error;
        console.warn(`[OSINT] ${err.message}`);
      }

      // Snapshot + diff
      const previous = loadPrevious<typeof collected>('web', domain);
      saveSnapshot('web', domain, collected);
      const diff = summarise(diffById(previous?.payload, collected, x => `${x.id}-${x.feature}`, x => `${x.status}-${x.description}`));

      send({
        type: 'done',
        message: `Scan complete — ${scanner.discoveredPages.size} page(s), ${scanner.jsResources.size} JS file(s) analysed.`,
        crawlTree: Object.fromEntries(scanner.crawlTree),
        diff,
      });
    }
  } catch (e: unknown) {
    const error = e as Error;
    send({ type: 'error', message: error.message ?? 'Unknown error during scan' });
  }

  res.end();
}
