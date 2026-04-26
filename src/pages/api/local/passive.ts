import type { NextApiRequest, NextApiResponse } from 'next';
import { passiveMonitor } from '@/utils/arpMonitor';

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({
    isRunning: passiveMonitor.isRunning(),
    devices: passiveMonitor.list(),
  });
}
