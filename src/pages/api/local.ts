/**
 * /api/local  — Local Network SSE Scan (Internal Audit)
 * 
 * POST { network }  (e.g., "192.168.1.0/24")
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { NmapScanner } from '@/utils/nmapScanner';

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

  const send = (data: { type: string; payload?: unknown; message?: string; current?: number; total?: number }) => {
    // Log to server CLI
    if (data.type === 'progress') {
       console.log(`\x1b[35m[LOCAL SCAN] ${data.message}\x1b[0m`);
    } else if (data.type === 'result') {
       const payload = data.payload as { feature: string; category: string; status: string };
       const { feature, category, status } = payload;
       const color = status === 'VULNERABLE' ? '\x1b[31m' : (status === 'WARNING' ? '\x1b[33m' : '\x1b[32m');
       console.log(`  └─ [${color}${status}\x1b[0m] ${category}: ${feature}`);
    }

    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  console.log(`\x1b[34m[LOCAL SCAN START] Network: ${target}\x1b[0m`);
  send({ type: 'progress', message: `Starting aggressive local audit: ${target}...`, current: 0, total: 1 });

  const nmap = new NmapScanner(target);

  try {
    const hosts = await nmap.localAudit();
    
    for (const host of hosts) {
      for (const p of host.ports) {
        // Base Port Info
        send({
          type: 'result',
          payload: {
             id: 10000 + p.portid,
             category: 'Local Network',
             feature: `Host: ${host.address} | Port: ${p.portid}/${p.protocol}`,
             status: 'NEUTRAL',
             description: `${p.service} ${p.product ?? ''} ${p.version ?? ''} (${p.state})`,
             finding: `Hostnames: ${host.hostnames.join(', ')}`,
             remediation: 'Ensure open ports on local network are necessary and password-protected.'
          }
        });

        // Script Findings
        if (p.scripts) {
           for (const [sid, output] of Object.entries(p.scripts)) {
              const status = (output.toLowerCase().includes('vulnerable') || output.toLowerCase().includes('exploit')) ? 'VULNERABLE' : 'WARNING';
              send({
                type: 'result',
                payload: {
                   id: 11000 + Math.floor(Math.random() * 9000),
                   category: 'Security Script',
                   feature: `${sid} on ${host.address}:${p.portid}`,
                   status,
                   description: output.substring(0, 1000),
                   finding: `Nmap script "${sid}" triggered a finding.`,
                   remediation: 'Apply relevant security patches and re-evaluate service exposure.'
                }
              });
           }
        }
      }
    }

    send({ type: 'done', message: `Local scan finished. Analyzed ${hosts.length} active host(s).` });

  } catch (e: unknown) {
    const error = e as Error;
    console.error(`\x1b[31m[LOCAL SCAN ERROR] ${error.message}\x1b[0m`);
    send({ type: 'error', message: error.message });
  }

  res.end();
}
