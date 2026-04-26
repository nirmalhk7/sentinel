import type { NextApiRequest, NextApiResponse } from 'next';
import { targetStore } from '@/utils/targetStore';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    return res.status(200).json({ targets: targetStore.list() });
  }
  if (req.method === 'POST') {
    const { value, label, modules } = req.body ?? {};
    if (!value || typeof value !== 'string') return res.status(400).json({ error: 'value required' });
    try {
      const t = targetStore.add(value, { label, modules });
      return res.status(200).json({ target: t });
    } catch (e) {
      const err = e as Error;
      return res.status(400).json({ error: err.message });
    }
  }
  return res.status(405).json({ error: 'Method not allowed' });
}
