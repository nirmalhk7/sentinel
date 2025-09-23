import { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";
import { readFile, unlink } from "fs/promises";
import { join } from "path";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  console.log(`[dnsrecon] API request received: ${req.method} ${req.url}`);
  
  if (req.method !== "POST") {
    console.error(`[dnsrecon] Invalid method: ${req.method}`);
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { domain } = req.body;
  console.log(`[dnsrecon] Request body:`, req.body);

  if (!domain || typeof domain !== "string") {
    console.error(`[dnsrecon] Invalid domain provided:`, domain);
    return res.status(400).json({ error: "Invalid domain" });
  }

  console.log(`[dnsrecon] Starting process for domain: ${domain}`);
  
  const timestamp = Date.now();
  const outputFile = join(process.cwd(), `${timestamp}.json`);
  const dnsreconProcess = spawn("dnsrecon", ["-d", domain, "-j", outputFile]);
  let errorOutput = "";

  const timeout = setTimeout(() => {
    console.error("[dnsrecon] Process timed out.");
    dnsreconProcess.kill();
    if (!res.headersSent) {
      res.status(500).json({ error: "Process timed out" });
    }
  }, 30000);

  dnsreconProcess.stderr.on("data", (data) => {
    const chunk = data.toString();
    errorOutput += chunk;
    console.error(`[dnsrecon] stderr: ${chunk}`);
  });

  dnsreconProcess.on("error", (err) => {
    console.error(`[dnsrecon] Failed to start process: ${err.message}`);
    clearTimeout(timeout);
    if (!res.headersSent) {
      res.status(500).json({ error: `Failed to start dnsrecon process: ${err.message}` });
    }
  });

  dnsreconProcess.on("close", async (code) => {
    clearTimeout(timeout);
    console.log(`[dnsrecon] Process closed with code: ${code}`);
    
    if (!res.headersSent) {
      if (code === 0) {
        try {
          const jsonData = await readFile(outputFile, 'utf-8');
          const parsedData = JSON.parse(jsonData);
          
          // Clean up the timestamp file
          await unlink(outputFile).catch((err) => {
            console.warn(`[dnsrecon] Failed to delete temp file: ${err.message}`);
          });
          
          console.log(`[dnsrecon] Sending JSON response with ${parsedData.length || 0} records`);
          
          res.status(200).json({ 
            success: true, 
            data: parsedData,
            command: `dnsrecon -d ${domain} -j ${outputFile}`
          });
        } catch (err) {
          console.error(`[dnsrecon] Failed to read/parse JSON output: ${err}`);
          
          // Clean up the timestamp file on error
          await unlink(outputFile).catch(() => {});
          
          res.status(500).json({ 
            error: `Failed to read JSON output: ${err instanceof Error ? err.message : 'Unknown error'}`,
            errorOutput: errorOutput
          });
        }
      } else {
        console.error(`[dnsrecon] Process failed with code ${code}`);
        
        // Clean up the timestamp file on error
        await unlink(outputFile).catch(() => {});
        
        res.status(500).json({ 
          error: `dnsrecon process failed with code ${code}`,
          errorOutput: errorOutput
        });
      }
    }
  });
}

