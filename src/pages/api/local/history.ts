import type { NextApiRequest, NextApiResponse } from 'next';
import { networkScanner, DEFAULT_TARGET } from '@/utils/networkScanner';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });
  const record = networkScanner.getLatest();
  return res.status(200).json({
    lastScan: networkScanner.getLastScanTime(),
    isRunning: networkScanner.isRunning(),
    defaultTarget: DEFAULT_TARGET,
    record,
  });
}
