/**
 * /api/osint  — Passive OSINT SSE stream
 *
 * POST { domain } → streams OsintFinding events (same shape as /api/scan/stream).
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { runOsint, listProviders } from '@/utils/osintScanner';
import { saveSnapshot } from '@/utils/snapshots';

export const config = { api: { responseLimit: false } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    return res.status(200).json({ providers: listProviders() });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST or GET only' });

  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain required' });

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (data: unknown) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
    if (typeof (res as unknown as { flush: () => void }).flush === 'function') (res as unknown as { flush: () => void }).flush();
  };

  send({ type: 'progress', message: `Starting passive OSINT for ${domain}…` });
  try {
    const findings = await runOsint(domain, {
      emit: (f) => send({ type: 'result', payload: f }),
    });
    saveSnapshot('osint', domain, findings);
    send({ type: 'done', message: `OSINT complete — ${findings.length} finding(s).` });
  } catch (e) {
    const err = e as Error;
    send({ type: 'error', message: err.message });
  }
  res.end();
}
