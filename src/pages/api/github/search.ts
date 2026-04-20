import type { NextApiRequest, NextApiResponse } from 'next';
import { githubScanner } from '@/utils/githubScanner';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // The scanner initializes its own background monitor upon first import.

  if (req.method === 'GET') {
    const history = githubScanner.getHistory();
    return res.status(200).json({
      lastScan: githubScanner.getLastScanTime(),
      results: history,
    });
  }

  if (req.method === 'POST' || (req.method === 'GET' && req.query.trigger === 'true')) {
    // Manually trigger a scan
    const results = await githubScanner.runScan();
    return res.status(200).json({
      message: 'Scan triggered manually',
      count: results.length,
      results: results,
    });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
