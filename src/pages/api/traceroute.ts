import type { NextApiRequest, NextApiResponse } from 'next';

const traceroute = require('traceroute');

interface TracerouteHop {
  hop: number;
  ip: string;
  domain?: string;
  rtt?: number;
}

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  console.log(`[traceroute] API request received: ${req.method} ${req.url}`);
  
  if (req.method !== 'POST') {
    console.error(`[traceroute] Invalid method: ${req.method}`);
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { domain } = req.body;
  console.log(`[traceroute] Request body:`, req.body);

  if (!domain || typeof domain !== 'string') {
    console.error(`[traceroute] Invalid domain provided:`, domain);
    return res.status(400).json({ error: 'Invalid domain' });
  }

  console.log(`[traceroute] Starting traceroute for domain: ${domain}`);

  traceroute.trace(domain, function (err: Error | null, hops: TracerouteHop[]) {
    if (err) {
      console.error(`[traceroute] Error occurred: ${err.message}`);
      return res.status(500).json({ 
        error: `Traceroute failed: ${err.message}`,
        success: false
      });
    }

    console.log(`[traceroute] Successfully traced ${domain} with ${hops.length} hops`);
    
    res.status(200).json({
      success: true,
      target: domain,
      hops: hops,
      totalHops: hops.length,
      command: `traceroute ${domain}`
    });
  });
}
