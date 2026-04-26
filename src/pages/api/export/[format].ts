/**
 * /api/export/[format]?target=...   format ∈ json | csv
 *
 * Bundles the latest snapshot from every module for the given target into one
 * downloadable artifact. PDF support intentionally left for later (would pull
 * in a heavy dependency).
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { loadLatest } from '@/utils/snapshots';
import { networkScanner } from '@/utils/networkScanner';
import { githubScanner } from '@/utils/githubScanner';

interface Finding { id?: number; category?: string; feature?: string; status?: string; description?: string }

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { format } = req.query;
  const target = String(req.query.target ?? '').trim();
  if (!target) return res.status(400).json({ error: 'target query param required' });

  const web = loadLatest<Finding[]>('web', target);
  const osint = loadLatest<Finding[]>('osint', target);
  const network = loadLatest<Finding[]>('network', target) ?? { payload: networkScanner.getLatest()?.results ?? [] };
  const github = githubScanner.getHistory().filter(r => r.repository.toLowerCase().includes(target.toLowerCase()));

  const bundle = {
    target,
    exportedAt: new Date().toISOString(),
    web: web?.payload ?? [],
    osint: osint?.payload ?? [],
    network: network?.payload ?? [],
    github,
  };

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="sentinel-${safe(target)}.json"`);
    return res.status(200).send(JSON.stringify(bundle, null, 2));
  }

  if (format === 'csv') {
    const rows: string[] = ['module,id,category,feature,status,description'];
    for (const [mod, list] of [['web', bundle.web], ['osint', bundle.osint], ['network', bundle.network]] as const) {
      for (const f of list as Finding[]) {
        rows.push([mod, f.id ?? '', csv(f.category), csv(f.feature), f.status ?? '', csv(f.description)].join(','));
      }
    }
    for (const r of github) {
      rows.push(['github', '', csv('Exposure'), csv(r.repository), r.isLikelySensitive ? 'VULNERABLE' : 'WARNING', csv(r.url)].join(','));
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="sentinel-${safe(target)}.csv"`);
    return res.status(200).send(rows.join('\n'));
  }

  return res.status(400).json({ error: 'format must be json or csv' });
}

function csv(v: unknown): string {
  if (v == null) return '';
  const s = String(v).replace(/"/g, '""');
  return /[",\n]/.test(s) ? `"${s}"` : s;
}

function safe(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
}
