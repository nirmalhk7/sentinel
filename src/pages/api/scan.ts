import { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { domain, phase } = req.body;

  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "Invalid domain" });
  }

  if (!phase || !["passive", "active", "vulnerability"].includes(phase)) {
    return res.status(400).json({ error: `Invalid phase: ${phase}`, received: phase });
  }

  const commands = [
    { name: "dnsrecon", command: "dnsrecon", args: ["-d", domain] },
    { name: "nmap", command: "nmap", args: ["-sV", "-sC", "-T4", domain] },
    { name: "nikto", command: "nikto", args: ["-h", domain, "-Format", "xml"] },
    { name: "whois", command: "whois", args: [domain] },
    { name: "subfinder", command: "subfinder", args: ["-d", domain] },
    { name: "theHarvester", command: "theHarvester", args: ["-d", domain, "-b", "all"] },
    { name: "ffuf", command: "ffuf", args: ["-w", "wordlist.txt", "-u", `${domain}/FUZZ`, "-o", "json", "-of", "json"] },
    { name: "curl", command: "curl", args: ["-sI", domain] },
    { name: "whatweb", command: "whatweb", args: [domain] },
    { name: "nuclei", command: "nuclei", args: ["-u", domain, "-json"] },
    { name: "sqlmap", command: "sqlmap", args: ["-u", domain] },
  ];

  const results: Record<string, any> = {};

  for (const { name, command, args } of commands) {
    console.log(`Running ${name}: ${command} ${args.join(" ")}`);

    try {
      const output = await new Promise<string>((resolve, reject) => {
        const process = spawn(command, args);

        let stdout = "";
        let stderr = "";

        process.stdout.on("data", (data) => {
          stdout += data.toString();
        });

        process.stderr.on("data", (data) => {
          stderr += data.toString();
        });

        process.on("close", (code) => {
          if (code === 0) {
            resolve(stdout);
          } else {
            reject(new Error(stderr || `Command ${name} failed with code ${code}`));
          }
        });
      });

      results[name] = { success: true, output };
    } catch (error: any) {
      console.error(`Error running ${name}: ${error.message}`);
      results[name] = { success: false, error: error.message };
    }
  }

  res.status(200).json({ results });
}
