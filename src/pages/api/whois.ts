import { NextApiRequest, NextApiResponse } from 'next';
import whois from 'whois';

interface WhoisResponse {
  success: boolean;
  data?: string;
  error?: string;
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<WhoisResponse>
) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({
      success: false,
      error: 'Domain parameter is required'
    });
  }

  if (typeof domain !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Domain must be a string'
    });
  }

  // Basic domain validation
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain.trim())) {
    return res.status(400).json({
      success: false,
      error: 'Invalid domain format'
    });
  }

  try {
    const whoisData = await new Promise<string>((resolve, reject) => {
      whois.lookup(domain.trim(), (err: Error | null, data: string) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });

    return res.status(200).json({
      success: true,
      data: whoisData
    });
  } catch (error) {
    console.error('Whois lookup error:', error);
    return res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    });
  }
}