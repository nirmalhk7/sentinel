import type { NextApiRequest, NextApiResponse } from 'next';
import { githubScanner } from '@/utils/githubScanner';

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json(githubScanner.health());
}
