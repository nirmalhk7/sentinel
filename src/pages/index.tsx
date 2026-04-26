import React, { useState, useRef, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';

interface ScanResult {
  id: number;
  category: string;
  feature: string;
  status: 'SAFE' | 'VULNERABLE' | 'WARNING' | 'NEUTRAL';
  description: string;
  finding?: string;
  remediation?: string;
}

interface ScanEvent {
  type: 'result' | 'progress' | 'done' | 'error';
  payload?: ScanResult;
  message?: string;
  current?: number;
  total?: number;
  crawlTree?: Record<string, { url: string; children: string[]; type: 'page' | 'js' | 'subdomain' | 'api' }>;
  diff?: { added: number; removed: number; changed: number; total: number };
}

const STATUS_CONFIG: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  VULNERABLE: { bg: 'bg-rose-500/10',    text: 'text-rose-400',    border: 'border-rose-500/30',    dot: 'bg-rose-400' },
  WARNING:    { bg: 'bg-amber-500/10',   text: 'text-amber-400',   border: 'border-amber-500/30',   dot: 'bg-amber-400' },
  SAFE:       { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  NEUTRAL:    { bg: 'bg-slate-500/10',   text: 'text-slate-400',   border: 'border-slate-600/30',   dot: 'bg-slate-500' },
};



export default function Scanner() {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isDone, setIsDone] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All (Critical)');
  const [totalSteps, setTotalSteps] = useState<number>(0);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [sortBy, setSortBy] = useState<'id' | 'status'>('id');
  const [crawlTree, setCrawlTree] = useState<Record<string, { url: string; children: string[]; type: string }> | null>(null);
  const [diff, setDiff] = useState<{ added: number; removed: number; changed: number; total: number } | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const startScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || isScanning) return;

    // Reset state
    setResults([]);
    setLogs([]);
    setError(null);
    setIsDone(false);
    setIsScanning(true);
    setFilter('All');
    setStatusFilter('All (Critical)');
    setTotalSteps(0);
    setCurrentStep(0);
    setCrawlTree(null);
    setDiff(null);

    const abortController = new AbortController();
    const apiRoute = '/api/scan/stream';
    const body = { domain: target.trim() };

    (async () => {
      try {
        const resp = await fetch(apiRoute, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: abortController.signal,
        });

        if (!resp.ok || !resp.body) {
          const err = await resp.json().catch(() => ({ error: 'Stream failed' }));
          setError(err.error ?? 'Stream failed');
          setIsScanning(false);
          return;
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          // SSE messages are separated by double newlines
          const parts = buffer.split('\n\n');
          buffer = parts.pop() ?? '';

          for (const part of parts) {
            const dataLine = part.split('\n').find(l => l.startsWith('data: '));
            if (!dataLine) continue;
            const json = dataLine.slice(6);
            if (json === '[DONE]') break;
            try {
              const event: ScanEvent = JSON.parse(json);
              if (event.type === 'result' && event.payload) {
                setResults(prev => [...prev, event.payload!]);
              } else if (event.type === 'progress' && event.message) {
                if (event.current != null) setCurrentStep(event.current);
                if (event.total != null) setTotalSteps(event.total);
                if (event.message === 'INIT_STATS') continue;
                setLogs(prev => [...prev, `⚡ ${event.message}`]);
              } else if (event.type === 'done') {
                setLogs(prev => [...prev, '✅ Scan complete!']);
                if (event.crawlTree) setCrawlTree(event.crawlTree);
                if (event.diff) setDiff(event.diff);
                setIsDone(true);
              } else if (event.type === 'error') {
                setError(event.message ?? 'Unknown error');
              }
            } catch {}
          }
        }
      } catch {
        setError('Connection lost');
      } finally {
        setIsScanning(false);
        setIsDone(true);
      }
    })();

    return () => { abortController.abort(); };
  };

  const stopScan = () => {
    eventSourceRef.current?.close();
    setIsScanning(false);
    setIsDone(true);
    setLogs(prev => [...prev, '⛔ Scan interrupted by user.']);
  };

  // Derived stats
  const counts = {
    total: results.length,
    vulnerable: results.filter(r => r.status === 'VULNERABLE').length,
    warning: results.filter(r => r.status === 'WARNING').length,
    safe: results.filter(r => r.status === 'SAFE').length,
    neutral: results.filter(r => r.status === 'NEUTRAL').length,
  };

  const riskScore = counts.total > 0
    ? Math.round(100 - ((counts.vulnerable * 3 + counts.warning * 1) / (counts.total * 3)) * 100)
    : null;

  const filteredResults = results
    .filter(r => r.status !== 'SAFE') // User requested: "The UI shouldnt show me Safe results"
    .filter(r => filter === 'All' || r.category === filter)
    .filter(r => statusFilter === 'All (Critical)' || r.status === statusFilter)
    .sort((a, b) => sortBy === 'id' ? a.id - b.id : ['VULNERABLE','WARNING','NEUTRAL'].indexOf(a.status) - ['VULNERABLE','WARNING','NEUTRAL'].indexOf(b.status));

  const categories = [...new Set(results.map(r => r.category))];

  return (
    <div className="min-h-screen bg-[#07090f] text-slate-200" style={{ fontFamily: '"Inter", system-ui, sans-serif' }}>
      <Head>
        <title>Sentinel | Security Scanner</title>
        <meta name="description" content="Real-time 40-point web security and intelligence assessment tool." />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&display=swap" />
      </Head>

      {/* ── Navbar ── */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#07090f]/80 backdrop-blur-md border-b border-slate-800/60">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-sky-600 rounded-lg flex items-center justify-center shadow-lg shadow-sky-600/20">
               <span className="text-white font-black text-xl">S</span>
            </div>
            <span className="text-white font-bold tracking-tight">SENTINEL <span className="text-sky-500">PRO</span></span>
          </div>
          <div className="flex gap-1 p-1 bg-slate-900/50 rounded-xl border border-slate-800">
            <Link
              href="/dashboard"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Dashboard
            </Link>
            <button
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition bg-sky-600 text-white`}
            >
              Website Audit
            </button>
            <Link
              href="/local"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Local Network
            </Link>
            <Link
              href="/github"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              GitHub Scan
            </Link>
          </div>
          <div className="hidden md:flex items-center gap-4">
             <span className="text-slate-500 text-[10px] font-bold uppercase tracking-widest">Version 2.4.0</span>
          </div>
        </div>
      </nav>

      {/* ── Hero ── */}
      <div className="relative overflow-hidden border-b border-slate-800/60 pt-16">
        <div className="absolute inset-0 pointer-events-none">
          <div className="w-full h-full opacity-15 blur-sm bg-slate-900" />
          <div className="absolute inset-0" style={{ background: 'linear-gradient(to bottom, #07090f 0%, transparent 40%, #07090f 100%)' }} />
        </div>

        <div className="relative z-10 max-w-4xl mx-auto px-6 pt-20 pb-16 text-center">
          <div className="inline-flex items-center gap-2 bg-sky-500/10 border border-sky-400/20 text-sky-400 text-xs font-bold uppercase tracking-widest px-4 py-1.5 rounded-full mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
            Multi-Point Security Audit + Intelligence
          </div>
 
          <h1 className="text-5xl font-black mb-4 leading-tight" style={{ background: 'linear-gradient(135deg, #fff 0%, #93c5fd 50%, #818cf8 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Security Assessment
          </h1>
          <p className="text-slate-400 text-base max-w-xl mx-auto mb-10">
            Streaming security analyzer — headers, TLS, cookies, DNS, WHOIS & crawl analysis delivered live.
          </p>

          <form onSubmit={startScan} className="relative group max-w-2xl mx-auto">
            <div className="absolute -inset-px rounded-2xl opacity-50 group-focus-within:opacity-100 transition-opacity"
              style={{ background: 'linear-gradient(135deg, #0ea5e9, #6366f1)', filter: 'blur(8px)' }} />
            <div className="relative flex items-center bg-[#111827] border border-slate-700 rounded-2xl p-1.5 gap-2">
              {/* Globe icon */}
              <div className="pl-3 text-slate-500 flex-shrink-0">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                </svg>
              </div>
               <input
                id="domain-input"
                type="text"
                placeholder="Enter domain (e.g. example.com or https://example.com)"
                className="flex-1 bg-transparent border-none focus:outline-none text-white placeholder-slate-500 text-sm py-3"
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={isScanning}
              />
              {isScanning ? (
                <button type="button" onClick={stopScan}
                  className="flex-shrink-0 bg-rose-600 hover:bg-rose-500 text-white text-sm font-bold px-5 py-2.5 rounded-xl transition">
                  Stop
                </button>
              ) : (
                <button type="submit" disabled={!target.trim()}
                  className="flex-shrink-0 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-bold px-5 py-2.5 rounded-xl transition shadow-lg shadow-sky-600/20">
                  Start Scan
                </button>
              )}
            </div>
          </form>

          {error && (
            <div className="mt-4 max-w-2xl mx-auto p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-sm">
              {error}
            </div>
          )}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="max-w-7xl mx-auto px-6 py-10 space-y-8">

        {/* Diff banner */}
        {diff && diff.total > 0 && (
          <div className="bg-sky-500/5 border border-sky-500/30 rounded-2xl p-4 flex flex-wrap items-center gap-4">
            <span className="text-[10px] font-black uppercase tracking-widest text-sky-400">Changes since last scan</span>
            <span className="text-emerald-400 text-sm font-bold">+{diff.added} new</span>
            <span className="text-rose-400 text-sm font-bold">-{diff.removed} resolved</span>
            <span className="text-amber-400 text-sm font-bold">~{diff.changed} changed</span>
          </div>
        )}

        {/* Progress Bar */}
        {(isScanning || isDone) && totalSteps > 0 && (
          <div className="bg-[#0d111a] border border-slate-800 rounded-2xl p-6">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Test Progress</h3>
                <p className="text-xs text-slate-500 mt-1">
                  {isScanning ? `Executing test suite...` : `Audit finished.`}
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-black text-white">{currentStep}</span>
                <span className="text-slate-600 font-bold text-sm ml-1">/ {totalSteps}</span>
              </div>
            </div>
            <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all duration-500"
                style={{ width: `${(currentStep / totalSteps) * 100}%` }}
              />
            </div>
            <div className="mt-3 flex justify-between text-[10px] font-bold uppercase tracking-widest text-slate-600">
               <span>Discovery Start</span>
               <span>{totalSteps - currentStep} Tests Remaining</span>
               <span>Complete</span>
            </div>
          </div>
        )}

        {/* Live Log Console */}
        {(isScanning || logs.length > 0) && (
          <div className="bg-[#0d111a] border border-slate-800 rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-3 border-b border-slate-800 bg-black/20">
              {isScanning && <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />}
              <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">Live Console</span>
              <span className="ml-auto text-xs text-slate-600">{filteredResults.length} issues(s) found</span>
            </div>
            <div className="h-36 overflow-y-auto p-4 font-mono text-xs text-slate-400 space-y-0.5">
              {logs.map((l, i) => <div key={i}>{l}</div>)}
              <div ref={logEndRef} />
            </div>
          </div>
        )}

        {/* Stats Bar */}
        {results.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
               { label: 'Security Score', val: riskScore != null ? `${riskScore}%` : '—', color: riskScore != null && riskScore < 50 ? 'text-rose-400' : riskScore != null && riskScore < 75 ? 'text-amber-400' : 'text-emerald-400' },
              { label: 'Security Risks', val: counts.vulnerable, color: 'text-rose-400' },
              { label: 'Warnings', val: counts.warning, color: 'text-amber-400' },
              { label: 'Completion', val: `${Math.round((currentStep / totalSteps) * 100)}%`, color: 'text-sky-400' },
              { label: 'Total Checks', val: totalSteps, color: 'text-slate-400' },
            ].map((c, i) => (
              <div key={i} className="bg-[#0d111a] border border-slate-800 rounded-2xl p-5">
                <div className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">{c.label}</div>
                <div className={`text-3xl font-black ${c.color}`}>{c.val}</div>
              </div>
            ))}
          </div>
        )}

        {/* Results table */}
        {results.length > 0 && (
          <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden">
            {/* Toolbar */}
            <div className="flex flex-wrap items-center gap-3 px-6 py-4 border-b border-slate-800 bg-black/20">
              <span className="text-sm font-bold text-white">Security Results</span>
              <div className="ml-auto flex flex-wrap gap-2">
                {/* Category filter */}
                <select
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  className="bg-[#111827] border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 ring-sky-500"
                >
                  <option value="All">All Categories</option>
                  {categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                {/* Status filter */}
                <select
                  value={statusFilter}
                  onChange={e => setStatusFilter(e.target.value)}
                  className="bg-[#111827] border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 ring-sky-500"
                >
                  {['All (Critical)', 'VULNERABLE', 'WARNING', 'NEUTRAL'].map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                {/* Sort */}
                <button
                  onClick={() => setSortBy(s => s === 'id' ? 'status' : 'id')}
                  className="bg-[#111827] border border-slate-700 text-slate-400 text-xs rounded-lg px-3 py-1.5 hover:text-white transition"
                >
                  Sort: {sortBy === 'id' ? '#ID' : 'Severity'}
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-slate-900/40">
                    {['#', 'Category', 'Check', 'Status', 'Details'].map(h => (
                      <th key={h} className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest border-b border-slate-800">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((r, i) => {
                    const s = STATUS_CONFIG[r.status];
                    return (
                      <tr key={`${r.id}-${i}`} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors group">
                        <td className="px-6 py-4 text-xs font-mono text-slate-600 w-12">{r.id}</td>
                        <td className="px-6 py-4 w-44">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-sky-500">{r.category}</span>
                        </td>
                        <td className="px-6 py-4 max-w-[200px]">
                          <span className="text-sm font-semibold text-white group-hover:text-sky-300 transition-colors line-clamp-2">{r.feature}</span>
                        </td>
                        <td className="px-6 py-4 w-32">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-black uppercase tracking-widest ${s.bg} ${s.text} ${s.border}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                            {r.status}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <p className="text-xs text-slate-400 leading-relaxed">{r.description}</p>
                          {r.finding && (
                            <p className="mt-1.5 text-xs text-slate-500 italic border-l-2 border-slate-700 pl-2">{r.finding}</p>
                          )}
                          {r.remediation && r.status !== 'SAFE' && r.status !== 'NEUTRAL' && (
                            <p className="mt-1.5 text-[10px] text-sky-600 font-medium">
                              🔧 {r.remediation}
                            </p>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {filteredResults.length === 0 && (
              <div className="py-12 text-center text-slate-600 text-sm">No results match the current filters.</div>
            )}
          </div>
        )}

        {/* ── Crawl Tree Builder ── */}
        {crawlTree && (
          <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden shadow-2xl shadow-sky-900/10">
            <div className="px-6 py-5 border-b border-slate-800 bg-black/20 flex items-center justify-between">
               <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                    Discovery Tree & Network Topology
                  </h3>
                  <p className="text-[10px] text-slate-500 font-medium uppercase tracking-widest mt-1">Found {Object.keys(crawlTree).length} unique nodes during crawl</p>
               </div>
               <div className="flex gap-4 text-[10px] font-bold uppercase tracking-widest text-slate-400">
                  <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Page</span>
                  <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-sky-400" /> Subdomain / Static</span>
                  <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-amber-400" /> API / JSON</span>
               </div>
            </div>
            <div className="p-6 overflow-x-auto max-h-[600px] overflow-y-auto">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {Object.entries(crawlTree).map(([url, node]) => (
                  <div key={url} className="bg-slate-900/40 border border-slate-800/60 rounded-2xl p-4 hover:border-sky-500/30 transition-all group">
                    <div className="flex items-start justify-between mb-3">
                       <div className="flex items-center gap-2">
                         <div className={`w-2 h-2 rounded-full ${node.type === 'api' ? 'bg-amber-400' : (node.type === 'js' || url.includes('.') && !url.endsWith('.html')) ? 'bg-sky-400' : 'bg-emerald-400'}`} />
                         <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">{node.type}</span>
                       </div>
                       <div className="text-[10px] text-slate-600 font-mono">{node.children.length} links</div>
                    </div>
                    <div className="text-xs font-bold text-slate-200 truncate mb-3 group-hover:text-white transition-colors" title={url}>
                      {url.replace(/^https?:\/\//, '')}
                    </div>
                    {node.children.length > 0 && (
                      <div className="space-y-1.5 border-t border-slate-800/50 pt-3">
                        {node.children.slice(0, 4).map((child, idx) => {
                          const childUrl = child.replace(/^https?:\/\//, '');
                          return (
                            <div key={idx} className="flex items-center gap-2 text-[10px] text-slate-500 hover:text-sky-400 transition-colors cursor-default">
                              <span className="text-slate-700">↳</span>
                              <span className="truncate">{childUrl.length > 40 ? childUrl.substring(0, 40) + '...' : childUrl}</span>
                            </div>
                          );
                        })}
                        {node.children.length > 4 && (
                           <div className="text-[9px] text-slate-600 italic pl-4 font-bold">+ {node.children.length - 4} more connections</div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!isScanning && results.length === 0 && !isDone && (
          <div className="flex flex-col items-center justify-center py-24 opacity-30">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 text-slate-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-slate-500 font-bold uppercase tracking-widest text-sm">Awaiting Target</p>
            <p className="text-slate-600 text-xs mt-1">Enter a domain above to start the audit</p>
          </div>
        )}
      </div>

      <footer className="border-t border-slate-900 py-10 text-center">
        <p className="text-slate-700 text-xs">Sentinel Security Audit Lab &mdash; for authorised security research only.</p>
      </footer>
    </div>
  );
}
