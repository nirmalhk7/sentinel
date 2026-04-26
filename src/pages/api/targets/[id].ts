import type { NextApiRequest, NextApiResponse } from 'next';
import { targetStore } from '@/utils/targetStore';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;
  if (typeof id !== 'string') return res.status(400).json({ error: 'id required' });

  if (req.method === 'GET') {
    const t = targetStore.get(id);
    if (!t) return res.status(404).json({ error: 'not found' });
    return res.status(200).json({ target: t });
  }
  if (req.method === 'DELETE') {
    const ok = targetStore.remove(id);
    if (!ok) return res.status(404).json({ error: 'not found' });
    return res.status(200).json({ removed: true });
  }
  if (req.method === 'PATCH') {
    const t = targetStore.update(id, req.body ?? {});
    if (!t) return res.status(404).json({ error: 'not found' });
    return res.status(200).json({ target: t });
  }
  return res.status(405).json({ error: 'Method not allowed' });
}
