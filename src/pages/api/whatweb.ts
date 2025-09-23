import { NextApiRequest, NextApiResponse } from "next";
import { handleProcess } from "@/utils/processHandler";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { domain } = req.body;

  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "Invalid domain" });
  }

  handleProcess("whatweb", [domain], res);
}
