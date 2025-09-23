import { NextApiResponse } from "next";
import { spawn } from "child_process";

export function handleProcess(
  command: string,
  args: string[],
  res: NextApiResponse,
  timeoutMs: number = 30000
) {
  console.log(`Executing command: ${command} ${args.join(" ")}`);

  const process = spawn(command, args);
  res.setHeader("Content-Type", "text/plain;charset=utf-8");

  const timeout = setTimeout(() => {
    console.error("Process timed out.");
    process.kill();
    if (!res.headersSent) {
      res.status(500).end("Process timed out.");
    }
  }, timeoutMs);

  process.stdout.on("data", (data) => {
    res.write(data.toString());
  });

  process.stderr.on("data", (data) => {
    console.error(`Error: ${data}`);
    res.write(data.toString());
  });

  process.on("error", (err) => {
    console.error(`Failed to start process: ${err.message}`);
    clearTimeout(timeout);
    if (!res.headersSent) {
      res.status(500).json({ error: `Failed to start process: ${command}`, details: err.message });
    }
  });

  process.on("close", (code) => {
    clearTimeout(timeout);
    if (!res.headersSent) {
      if (code === 0) {
        res.end();
      } else {
        res.status(500).json({ error: `${command} process failed`, code });
      }
    }
  });
}
