import type { NextApiRequest, NextApiResponse } from 'next';
import { githubScanner } from '@/utils/githubScanner';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendResult = (result: import('@/utils/githubScanner').GitHubEnvResult) => {
    res.write(`data: ${JSON.stringify(result)}\n\n`);
  };

  githubScanner.on('result', sendResult);

  req.on('close', () => {
    githubScanner.off('result', sendResult);
    res.end();
  });
}
