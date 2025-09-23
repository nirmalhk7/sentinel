import type { NextApiRequest, NextApiResponse } from 'next';

const sslChecker = require('ssl-checker');

interface SSLInfo {
  valid: boolean;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  validFor: string[];
  issuer: {
    C?: string;
    ST?: string;
    L?: string;
    O?: string;
    CN?: string;
  };
  fingerprint: string;
  serialNumber: string;
  raw: any;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  console.log(`[ssl-checker] API request received: ${req.method} ${req.url}`);
  
  if (req.method !== 'POST') {
    console.error(`[ssl-checker] Invalid method: ${req.method}`);
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { domain, port = 443 } = req.body;
  console.log(`[ssl-checker] Request body:`, req.body);

  if (!domain || typeof domain !== 'string') {
    console.error(`[ssl-checker] Invalid domain provided:`, domain);
    return res.status(400).json({ error: 'Invalid domain' });
  }

  console.log(`[ssl-checker] Checking SSL for: ${domain}:${port}`);

  try {
    const sslInfo: SSLInfo = await sslChecker(domain, {
      method: 'GET',
      port: port,
      protocol: 'https:',
      agent: false,
      timeout: 10000
    });

    console.log(`[ssl-checker] SSL check completed for ${domain}`);
    console.log(`[ssl-checker] Certificate valid: ${sslInfo.valid}, Days remaining: ${sslInfo.daysRemaining}`);

    res.status(200).json({
      success: true,
      domain: domain,
      port: port,
      data: {
        valid: sslInfo.valid,
        validFrom: sslInfo.validFrom,
        validTo: sslInfo.validTo,
        daysRemaining: sslInfo.daysRemaining,
        validFor: sslInfo.validFor,
        issuer: sslInfo.issuer,
        fingerprint: sslInfo.fingerprint,
        serialNumber: sslInfo.serialNumber,
        isExpired: sslInfo.daysRemaining <= 0,
        isExpiringSoon: sslInfo.daysRemaining <= 30,
        certificateAge: sslInfo.raw ? Math.floor((Date.now() - new Date(sslInfo.validFrom).getTime()) / (1000 * 60 * 60 * 24)) : null
      },
      command: `ssl-checker ${domain}:${port}`
    });

  } catch (error) {
    console.error(`[ssl-checker] Error checking SSL for ${domain}:`, error);
    
    res.status(500).json({
      success: false,
      error: `SSL check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      domain: domain,
      port: port
    });
  }
}