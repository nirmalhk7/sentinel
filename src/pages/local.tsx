import Head from 'next/head';
import Link from 'next/link';
import { useState, useEffect, useRef } from 'react';

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
  diff?: { added: number; removed: number; changed: number; total: number };
}

interface PassiveDevice {
  identifier: string;
  ip?: string;
  mac?: string;
  hostname?: string;
  source: 'arp' | 'mdns' | 'ssdp';
  service?: string;
  meta?: string;
  firstSeen: string;
  lastSeen: string;
}

const STATUS_CONFIG: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  VULNERABLE: { bg: 'bg-rose-500/10',    text: 'text-rose-400',    border: 'border-rose-500/30',    dot: 'bg-rose-400' },
  WARNING:    { bg: 'bg-amber-500/10',   text: 'text-amber-400',   border: 'border-amber-500/30',   dot: 'bg-amber-400' },
  SAFE:       { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  NEUTRAL:    { bg: 'bg-slate-500/10',   text: 'text-slate-400',   border: 'border-slate-600/30',   dot: 'bg-slate-500' },
};

export default function LocalScanner() {
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
  const [lastScan, setLastScan] = useState<number>(0);
  const [diff, setDiff] = useState<{ added: number; removed: number; changed: number; total: number } | null>(null);
  const [tab, setTab] = useState<'active' | 'passive'>('active');
  const [passiveDevices, setPassiveDevices] = useState<PassiveDevice[]>([]);
  const [passiveRunning, setPassiveRunning] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const runScan = (scanTarget: string) => {
    const trimmed = scanTarget.trim();
    if (!trimmed || isScanning) return;

    setResults([]);
    setLogs([]);
    setError(null);
    setIsDone(false);
    setIsScanning(true);
    setFilter('All');
    setStatusFilter('All (Critical)');
    setTotalSteps(0);
    setCurrentStep(0);

    const abortController = new AbortController();
    const apiRoute = '/api/local';
    const body = { network: trimmed };

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
                setLogs(prev => [...prev, `⚡ ${event.message}`]);
              } else if (event.type === 'done') {
                setLogs(prev => [...prev, '✅ Scan complete!']);
                setIsDone(true);
                setLastScan(Date.now());
                if (event.diff) setDiff(event.diff);
              } else if (event.type === 'error') {
                setError(event.message ?? 'Unknown error');
              }
            } catch {}
          }
        }
      } catch (e: unknown) {
        const error = e as Error;
        if (error.name !== 'AbortError') setError(error.message);
      } finally {
        setIsScanning(false);
        setIsDone(true);
      }
    })();

    return () => { abortController.abort(); };
  };

  const startScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(target);
  };

  // On mount: load cached cron result. If none, auto-trigger a scan with the default target.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/local/history');
        const data = await res.json();
        if (cancelled) return;
        const initialTarget = data?.record?.target || data?.defaultTarget || '';
        setTarget(initialTarget);
        if (data?.record?.results?.length) {
          setResults(data.record.results);
          setLastScan(data.lastScan || 0);
          setIsDone(true);
        } else if (initialTarget) {
          runScan(initialTarget);
        }
      } catch {
        // If the history endpoint fails, leave the form blank so user can scan manually.
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Refresh passive devices every 10s
  useEffect(() => {
    let cancelled = false;
    const fetchPassive = async () => {
      try {
        const res = await fetch('/api/local/passive');
        const data = await res.json();
        if (!cancelled) {
          setPassiveDevices(data.devices ?? []);
          setPassiveRunning(!!data.isRunning);
        }
      } catch {}
    };
    fetchPassive();
    const t = setInterval(fetchPassive, 10_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const stopScan = () => {
    setIsScanning(false);
    setIsDone(true);
    setLogs(prev => [...prev, '⛔ Scan interrupted by user.']);
  };

  const counts = {
    total: results.length,
    vulnerable: results.filter(r => r.status === 'VULNERABLE').length,
    warning: results.filter(r => r.status === 'WARNING').length,
  };

  const riskScore = counts.total > 0
    ? Math.round(100 - ((counts.vulnerable * 3 + counts.warning * 1) / (counts.total * 3)) * 100)
    : null;

  const filteredResults = results
    .filter(r => r.status !== 'SAFE')
    .filter(r => filter === 'All' || r.category === filter)
    .filter(r => statusFilter === 'All (Critical)' || r.status === statusFilter)
    .sort((a, b) => a.id - b.id);

  const categories = [...new Set(results.map(r => r.category))];

  return (
    <div className="min-h-screen bg-[#07090f] text-slate-200" style={{ fontFamily: '"Inter", system-ui, sans-serif' }}>
      <Head>
        <title>Internal Audit | Sentinel</title>
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
            <Link
              href="/dashboard"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Dashboard
            </Link>
            <Link
              href="/"
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center`}
            >
              Website Audit
            </Link>
            <button
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition bg-sky-600 text-white cursor-default`}
            >
              Local Network
            </button>
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

      <div className="relative pt-32 pb-16 border-b border-slate-800/60 overflow-hidden">
        <div className="absolute inset-0 pointer-events-none opacity-10 bg-[url('/audit-header.png')] bg-cover grayscale" />
        <div className="max-w-4xl mx-auto px-6 text-center">
          <div className="inline-flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-[10px] font-black uppercase tracking-[0.2em] px-4 py-1.5 rounded-full mb-6">
            Deep Internal Audit Mode
          </div>
          <h1 className="text-6xl font-black mb-4 tracking-tighter text-white">INTERNAL AUDIT</h1>
          <p className="text-slate-400 max-w-xl mx-auto mb-10 text-sm">Enhanced network discovery and security assessment for private ranges.</p>

          <form onSubmit={startScan} className="max-w-2xl mx-auto flex gap-2 bg-slate-900/50 p-2 rounded-2xl border border-slate-800 focus-within:border-sky-500 transition-all shadow-2xl">
            <input 
              type="text"
              placeholder="Target Network (e.g. 192.168.1.0/24)"
              className="flex-1 bg-transparent border-none focus:outline-none px-4 text-sm text-white"
              value={target}
              onChange={e => setTarget(e.target.value)}
              disabled={isScanning}
            />
            {isScanning ? (
              <button type="button" onClick={stopScan} className="bg-rose-600 px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest flex-shrink-0">Stop</button>
            ) : (
              <button type="submit" disabled={!target.trim()} className="bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest flex-shrink-0 transition">Run Audit</button>
            )}
          </form>
          {lastScan > 0 && (
            <p className="mt-4 text-[10px] text-slate-500 font-bold uppercase tracking-widest">
              Last Cron Scan: {new Date(lastScan).toLocaleString()}
            </p>
          )}

          {error && <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-xs">{error}</div>}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-10 space-y-8">
        {/* Tab switcher: Active vs Passive */}
        <div className="flex gap-2 p-1 bg-slate-900/50 rounded-xl border border-slate-800 w-fit">
          <button
            onClick={() => setTab('active')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition ${tab === 'active' ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            Active Audit
          </button>
          <button
            onClick={() => setTab('passive')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-2 ${tab === 'passive' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            Passive Listen
            {passiveRunning && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
            <span className="text-[10px] opacity-70">{passiveDevices.length}</span>
          </button>
        </div>

        {tab === 'active' && diff && diff.total > 0 && (
          <div className="bg-sky-500/5 border border-sky-500/30 rounded-2xl p-4 flex flex-wrap items-center gap-4">
            <span className="text-[10px] font-black uppercase tracking-widest text-sky-400">Changes since last scan</span>
            <span className="text-emerald-400 text-sm font-bold">+{diff.added} new</span>
            <span className="text-rose-400 text-sm font-bold">-{diff.removed} resolved</span>
            <span className="text-amber-400 text-sm font-bold">~{diff.changed} changed</span>
          </div>
        )}

        {tab === 'passive' && (
          <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 bg-emerald-500/5 flex items-center justify-between">
              <div>
                <span className="text-sm font-bold text-white uppercase tracking-widest">Passive Discovery</span>
                <p className="text-[10px] text-slate-500 mt-1">ARP table + mDNS (5353) + SSDP (1900). Listen-only, no probes.</p>
              </div>
              <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-1 rounded ${passiveRunning ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-slate-700/30 text-slate-500 border border-slate-700'}`}>
                {passiveRunning ? 'Listening' : 'Idle'}
              </span>
            </div>
            {passiveDevices.length > 0 ? (
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-slate-950/50">
                    {['Source', 'IP', 'MAC / ID', 'Service', 'First Seen', 'Last Seen'].map(h => (
                      <th key={h} className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {passiveDevices.map(d => (
                    <tr key={d.identifier} className="border-t border-slate-800/50 hover:bg-slate-800/20">
                      <td className="px-6 py-3 text-[10px] font-bold uppercase tracking-widest text-emerald-400">{d.source}</td>
                      <td className="px-6 py-3 text-xs text-white font-mono">{d.ip ?? '—'}</td>
                      <td className="px-6 py-3 text-xs text-slate-400 font-mono break-all">{d.mac ?? d.identifier.slice(0, 40)}</td>
                      <td className="px-6 py-3 text-xs text-slate-400">{d.service ?? '—'}{d.meta ? ` · ${d.meta}` : ''}</td>
                      <td className="px-6 py-3 text-[10px] text-slate-500">{new Date(d.firstSeen).toLocaleString()}</td>
                      <td className="px-6 py-3 text-[10px] text-slate-500">{new Date(d.lastSeen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-12 text-center text-slate-600 text-xs">No devices observed yet — listeners pick things up over time as devices broadcast.</div>
            )}
          </div>
        )}

        {tab === 'active' && (isScanning || isDone) && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
             <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 md:col-span-1">
                <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Risk Score</div>
                <div className={`text-4xl font-black ${riskScore && riskScore < 50 ? 'text-rose-500' : 'text-emerald-500'}`}>{riskScore ?? 0}%</div>
             </div>
             <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 md:col-span-3">
               <div className="flex justify-between items-center mb-3">
                  <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest line-clamp-1">{isScanning ? 'Executing test suite...' : 'Scan Complete'}</span>
                  <span className="text-white text-xs font-black tracking-tighter">{currentStep} / {totalSteps}</span>
               </div>
               <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                 <div className="h-full bg-sky-500 transition-all duration-500" style={{ width: `${(currentStep / totalSteps) * 100}%` }} />
               </div>
             </div>
          </div>
        )}

        {tab === 'active' && (isScanning || logs.length > 0) && (
          <div className="bg-black border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
            <div className="bg-slate-900/50 px-5 py-2 border-b border-slate-800 text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" /> Audit Logs
            </div>
            <div className="h-40 overflow-y-auto p-4 font-mono text-[11px] text-slate-400 space-y-0.5 scrollbar-thin scrollbar-thumb-slate-800">
               {logs.map((l, i) => <div key={i}>{l}</div>)}
               <div ref={logEndRef} />
            </div>
          </div>
        )}

        {tab === 'active' && results.length > 0 && (
          <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
             <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-black/20">
                <span className="text-xs font-black uppercase tracking-widest text-white">Audit Results</span>
                <div className="flex gap-2">
                   <select value={filter} onChange={e => setFilter(e.target.value)} className="bg-slate-950 border border-slate-800 text-[10px] uppercase font-bold text-slate-400 px-3 py-1.5 rounded-lg outline-none">
                      <option value="All">All Categories</option>
                      {categories.map(c => <option key={c} value={c}>{c}</option>)}
                   </select>
                </div>
             </div>
             <table className="w-full text-left border-collapse">
                <thead>
                   <tr className="bg-slate-950/50">
                      <th className="px-6 py-3 text-[9px] font-black text-slate-600 uppercase tracking-widest">ID</th>
                      <th className="px-6 py-3 text-[9px] font-black text-slate-600 uppercase tracking-widest">Target Check</th>
                      <th className="px-6 py-3 text-[9px] font-black text-slate-600 uppercase tracking-widest">Status</th>
                      <th className="px-6 py-3 text-[9px] font-black text-slate-600 uppercase tracking-widest">Finding</th>
                   </tr>
                </thead>
                <tbody>
                   {filteredResults.map((r, i) => {
                      const s = STATUS_CONFIG[r.status];
                      return (
                        <tr key={i} className="border-t border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                           <td className="px-6 py-5 text-xs font-mono text-slate-700">{r.id}</td>
                           <td className="px-6 py-5">
                              <div className="text-[10px] font-black text-sky-500 uppercase tracking-wider mb-1">{r.category}</div>
                              <div className="text-sm font-bold text-white tracking-tight">{r.feature}</div>
                           </td>
                           <td className="px-6 py-5">
                              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded border text-[9px] font-black uppercase tracking-widest ${s.bg} ${s.text} ${s.border}`}>
                                 {r.status}
                              </span>
                           </td>
                           <td className="px-6 py-5 text-xs text-slate-400 leading-relaxed max-w-md">
                              {r.description}
                              {r.remediation && <div className="mt-2 text-sky-500/80 font-bold tracking-tight">🔧 {r.remediation}</div>}
                           </td>
                        </tr>
                      );
                   })}
                </tbody>
             </table>
          </div>
        )}
      </div>

      <footer className="py-20 text-center opacity-30">
        <p className="text-xs font-black uppercase tracking-widest tracking-widest">Sentinel Internal Audit Engine v2.4</p>
      </footer>
    </div>
  );
}
