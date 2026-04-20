import React, { useState, useEffect, useMemo } from 'react';
import Head from 'next/head';

interface EnvPair {
  key: string;
  value: string;
}

interface GitHubEnvResult {
  repository: string;
  url: string;
  contentSnippet: string;
  foundAt: string;
  isLikelySensitive: boolean;
  extractedEnvs: EnvPair[];
}

export default function GitHubScanner() {
  const [results, setResults] = useState<GitHubEnvResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScan, setLastScan] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const res = await fetch('/api/github/search');
      const data = await res.json();
      setResults(data.results || []);
      setLastScan(data.lastScan);
    } catch (e) {
      setError('Failed to fetch data');
    }
  };

  useEffect(() => {
    fetchData();
    
    // Connect to real-time SSE stream
    const eventSource = new EventSource('/api/github/stream');
    
    eventSource.onmessage = (event) => {
      const newResult = JSON.parse(event.data);
      setResults(prev => {
        // Prevent duplicates
        if (prev.find(r => r.url === newResult.url)) return prev;
        return [newResult, ...prev];
      });
    };

    eventSource.onerror = () => {
      eventSource.close();
      // Reconnect after 5 seconds if connection is lost
      setTimeout(() => {
        // Simple logic to trigger a re-render or re-setup if needed
      }, 5000);
    };

    return () => {
      eventSource.close();
    };
  }, []);

  const triggerScan = async () => {
    setIsScanning(true);
    setError(null);
    try {
      const res = await fetch('/api/github/search', { method: 'POST' });
      const data = await res.json();
      setResults(data.results || []);
      setLastScan(Date.now());
    } catch (e) {
      setError('Failed to trigger scan');
    } finally {
      setIsScanning(false);
    }
  };

  // Aggregate all env pairs for the "All Env Values" section
  const allEnvValues = useMemo(() => {
    const list: (EnvPair & { repository: string; url: string; foundAt: string })[] = [];
    results.forEach(r => {
      if (r.extractedEnvs) {
        r.extractedEnvs.forEach(pair => {
          list.push({ ...pair, repository: r.repository, url: r.url, foundAt: r.foundAt });
        });
      }
    });
    return list.sort((a, b) => new Date(b.foundAt).getTime() - new Date(a.foundAt).getTime());
  }, [results]);

  return (
    <div className="min-h-screen bg-[#07090f] text-slate-200" style={{ fontFamily: '"Inter", system-ui, sans-serif' }}>
      <Head>
        <title>GitHub Exposure Scan | Sentinel</title>
      </Head>

      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#07090f]/80 backdrop-blur-md border-b border-slate-800/60">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-sky-600 rounded-lg flex items-center justify-center shadow-lg shadow-sky-600/20">
               <span className="text-white font-black text-xl">S</span>
            </div>
            <span className="text-white font-bold tracking-tight">SENTINEL <span className="text-sky-500">PRO</span></span>
          </div>
          <div className="flex gap-1 p-1 bg-slate-900/50 rounded-xl border border-slate-800">
            <a 
              href="/"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Website Audit
            </a>
            <a 
              href="/local"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Local Network
            </a>
            <button 
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition bg-sky-600 text-white cursor-default`}
            >
              GitHub Scan
            </button>
          </div>
          <div className="hidden md:flex items-center gap-4">
             <span className="text-slate-500 text-[10px] font-bold uppercase tracking-widest">Version 2.4.0</span>
          </div>
        </div>
      </nav>

      <div className="relative pt-32 pb-16 border-b border-slate-800/60 overflow-hidden">
        <div className="absolute inset-0 pointer-events-none opacity-10 bg-[url('https://images.unsplash.com/photo-1618401471353-b98aadebc25a?q=80&w=2000&auto=format&fit=crop')] bg-cover grayscale" />
        <div className="max-w-4xl mx-auto px-6 text-center relative z-10">
          <div className="inline-flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-black uppercase tracking-[0.2em] px-4 py-1.5 rounded-full mb-6">
            Automated Exposure Discovery
          </div>
          <h1 className="text-6xl font-black mb-4 tracking-tighter text-white uppercase">GitHub Exposure Monitor</h1>
          <p className="text-slate-400 max-w-xl mx-auto mb-10 text-sm">
            Analysis of repositories for potentially exposed credentials and environment files. Powered by scheduled scans through rotating nodes.
          </p>

          <div className="flex justify-center gap-4">
            <button 
              onClick={triggerScan}
              disabled={isScanning}
              className={`px-8 py-3 rounded-2xl text-sm font-black uppercase tracking-widest transition shadow-2xl ${isScanning ? 'bg-slate-700 text-slate-500' : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/20'}`}
            >
              {isScanning ? 'Scan in Progress...' : 'Trigger Manual Scan'}
            </button>
          </div>
          
          {lastScan > 0 && (
            <p className="mt-4 text-[10px] text-slate-500 font-bold uppercase tracking-widest">
              Last Scan: {new Date(lastScan).toLocaleString()}
            </p>
          )}

          {error && <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-xs">{error}</div>}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-10 space-y-12">
        {/* NEW SECTION: All Env Values */}
        <section>
          <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden shadow-2xl">
            <div className="px-6 py-5 border-b border-slate-800 bg-emerald-500/5 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 uppercase tracking-widest">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Raw Exposure Intelligence
              </h3>
              <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
                {allEnvValues.length} variables extracted
              </span>
            </div>

            <div className="overflow-x-auto max-h-[500px] overflow-y-auto custom-scrollbar">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 z-10">
                  <tr className="bg-slate-950">
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Key</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Value</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Source Repo</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Discovered</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {allEnvValues.map((item, i) => (
                    <tr key={i} className="hover:bg-emerald-500/5 transition-colors group">
                      <td className="px-6 py-4">
                        <code className="text-emerald-400 font-mono text-[11px] font-bold">{item.key}</code>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <code className="text-slate-300 font-mono text-[11px] bg-black/40 px-2 py-1 rounded border border-slate-800 break-all">
                            {item.value}
                          </code>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-xs text-slate-500 hover:text-sky-400 transition-colors">
                          {item.repository}
                        </a>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-[10px] text-slate-600 font-mono">
                          {new Date(item.foundAt).toLocaleTimeString()}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {allEnvValues.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-6 py-20 text-center text-slate-600 text-xs font-bold uppercase tracking-widest">
                        Waiting for extraction results...
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* Original Intelligence Feed */}
        <section>
          <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden shadow-2xl">
            <div className="px-6 py-5 border-b border-slate-800 bg-black/20 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 uppercase tracking-widest">
                Source Repository Feed
              </h3>
              <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
                Showing {results.length} unique files
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-slate-950/50">
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Repository</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Content Preview</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Risk Level</th>
                    <th className="px-6 py-4 text-[9px] font-black text-slate-600 uppercase tracking-widest">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i} className="border-t border-slate-800/50 hover:bg-slate-800/10 transition-colors group">
                      <td className="px-6 py-5">
                        <div className="text-sm font-bold text-white tracking-tight">{r.repository}</div>
                      </td>
                      <td className="px-6 py-5">
                        <div className="bg-black/40 border border-slate-800 rounded-lg p-3 font-mono text-[10px] text-slate-400 max-w-md truncate group-hover:text-emerald-400 transition-colors">
                          {r.contentSnippet}
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        {r.isLikelySensitive ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[9px] font-black uppercase tracking-widest">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" /> CRITICAL
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[9px] font-black uppercase tracking-widest">
                             MODERATE
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-5">
                        <a 
                          href={r.url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-sky-500 hover:text-sky-400 text-[10px] font-black uppercase tracking-widest transition flex items-center gap-1"
                        >
                          View Source
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                          </svg>
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {results.length === 0 && (
              <div className="py-24 text-center">
                <div className="w-16 h-16 bg-slate-900 rounded-full flex items-center justify-center mx-auto mb-4 border border-slate-800">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <p className="text-slate-500 font-bold uppercase tracking-widest text-xs">No Exposures Detected</p>
                <p className="text-slate-700 text-[10px] mt-1">Start a scan or wait for the automatic monitor to fire.</p>
              </div>
            )}
          </div>
        </section>
      </div>

      <style jsx>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: #07090f;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #1e293b;
          border-radius: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #334155;
        }
      `}</style>

      <footer className="py-20 text-center opacity-30">
        <p className="text-xs font-black uppercase tracking-widest">Sentinel Repository Security Monitor v1.1</p>
      </footer>
    </div>
  );
}
