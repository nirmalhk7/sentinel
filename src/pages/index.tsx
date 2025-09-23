import { useState } from "react";
import axios from "axios";
import Image from "next/image";
import Head from "next/head";

export default function Scanner() {
  const [domain, setDomain] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const [scanResults, setScanResults] = useState<any>(null);

  const handleScan = async () => {
    if (!domain) {
      setLogs((prevLogs) => [...prevLogs, "Please enter a valid domain."]);
      return;
    }

    setLogs((prevLogs) => [...prevLogs, `Starting scan for: ${domain}`]);

    const apis = ["/api/dnsrecon", "/api/nmap", "/api/nikto", "/api/whatweb"];
    const results: Record<string, { success: boolean; output?: string; error?: string }> = {};

    for (const api of apis) {
      try {
        const response = await axios.post(api, { domain });
        results[api] = { success: true, output: response.data.rawOutput };
        setLogs((prevLogs) => [...prevLogs, `Success: ${api}`]);
      } catch (error: any) {
        results[api] = { success: false, error: error.response?.data?.error || error.message };
        setLogs((prevLogs) => [...prevLogs, `Error: ${api} - ${results[api].error}`]);
      }
    }

    setScanResults(results);
  };

  return (
    <>
      <Head>
        <title>Recon Lab</title>
        <meta name="description" content="Recon Lab - A powerful reconnaissance and vulnerability scanning tool." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 dark:text-white">
        <div className="top-4 left-4 z-10">
          <Image
            src="/logo.png"
            alt="Logo"
            width={400}
            height={400}
          />
        </div>
        <main className="px-8 py-10">
          <div className="mb-6">
            <label htmlFor="domain" className="block text-lg font-medium mb-2">
              Enter Domain to Scan:
            </label>
            <div className="flex gap-2">
              <input
                id="domain"
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="flex-1 px-4 py-2 border border-zinc-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-sky-400"
                placeholder="e.g., example.com"
              />
              <button
                onClick={handleScan}
                className="px-4 py-2 bg-sky-500 text-white rounded-lg shadow hover:bg-sky-600 focus:outline-none focus:ring-2 focus:ring-sky-400"
              >
                Start Scan
              </button>
            </div>
          </div>

          <div className="mb-6">
            <h2 className="text-xl font-semibold mb-4">Live Console Log</h2>
            <div className="h-64 bg-zinc-900 text-white p-4 rounded-lg overflow-y-auto shadow-inner">
              {logs.length === 0 ? (
                <p className="text-zinc-500">No logs yet...</p>
              ) : (
                logs.map((log, index) => (
                  <pre key={index} className="text-sm whitespace-pre-wrap">
                    {log}
                  </pre>
                ))
              )}
            </div>
          </div>

          {scanResults && (
            <div className="mb-6">
              <h2 className="text-xl font-semibold mb-4">Structured Data Tables</h2>
              {Object.entries(scanResults).map(([api, result]) => {
                const typedResult = result as { success: boolean; output?: string; error?: string };
                return (
                  <div key={api} className="mb-4">
                    <h3 className="text-lg font-medium mb-2">{api}</h3>
                    {typedResult.success ? (
                      <pre className="bg-zinc-100 p-4 rounded-lg overflow-x-auto">
                        {typedResult.output}
                      </pre>
                    ) : (
                      <p className="text-red-500">Error: {typedResult.error}</p>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          <div>
            <h2 className="text-xl font-semibold mb-4">Asset Graph Visualization</h2>
            <p className="text-zinc-500">(Graph visualization will appear here after the scan)</p>
          </div>
        </main>
      </div>
    </>
  );
}
