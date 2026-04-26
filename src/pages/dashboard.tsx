import React, { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';

interface DiffSummary { added: number; removed: number; changed: number; total: number }

interface DashboardTarget {
  id: string;
  value: string;
  kind: 'domain' | 'cidr' | 'ip';
  label?: string;
  modules: { web: boolean; network: boolean; osint: boolean };
  addedAt: string;
  lastScannedAt?: string;
  lastRiskScore?: number;
  snapshots: { web: number; osint: number; network: number };
  recentDiffs: Record<string, DiffSummary>;
}

interface DashboardData {
  targets: DashboardTarget[];
  network: { lastScan: number; isRunning: boolean; hostCount: number };
  github: { proxyCount: number; tokenCount: number; queryCount: number; totalResults: number; lastScanTime: number; isScanning: boolean };
  passive: { isRunning: boolean; deviceCount: number };
  osintProviders: { name: string; enabled: boolean; hint: string }[];
  webhookConfigured: boolean;
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [newTarget, setNewTarget] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const res = await fetch('/api/dashboard');
      const json = await res.json();
      setData(json);
    } catch {
      setError('Failed to load dashboard');
    }
  };

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15_000);
    return () => clearInterval(t);
  }, []);

  const addTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;
    setAdding(true);
    setError(null);
    try {
      const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: newTarget.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setError(err.error || 'Failed to add');
      } else {
        setNewTarget('');
        refresh();
      }
    } finally {
      setAdding(false);
    }
  };

  const removeTarget = async (id: string) => {
    if (!confirm('Remove this target?')) return;
    await fetch(`/api/targets/${encodeURIComponent(id)}`, { method: 'DELETE' });
    refresh();
  };

  const enabledProviders = data?.osintProviders?.filter(p => p.enabled).length ?? 0;
  const totalProviders = data?.osintProviders?.length ?? 0;

  return (
    <div className="min-h-screen bg-[#07090f] text-slate-200" style={{ fontFamily: '"Inter", system-ui, sans-serif' }}>
      <Head>
        <title>Dashboard | Sentinel</title>
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
            <button className="px-4 py-1.5 rounded-lg text-xs font-bold transition bg-sky-600 text-white">Dashboard</button>
            <Link href="/" className="px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center">Website</Link>
            <Link href="/local" className="px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center">Local Network</Link>
            <Link href="/github" className="px-4 py-1.5 rounded-lg text-xs font-bold transition text-slate-400 hover:text-white flex items-center">GitHub Scan</Link>
          </div>
          <span className="text-slate-500 text-[10px] font-bold uppercase tracking-widest hidden md:block">Version 2.5.0</span>
        </div>
      </nav>

      <div className="pt-24 max-w-7xl mx-auto px-6 pb-20 space-y-8">
        {/* Hero / add target */}
        <div className="bg-[#0d111a] border border-slate-800 rounded-3xl p-8">
          <h1 className="text-4xl font-black text-white tracking-tighter mb-2">Targets</h1>
          <p className="text-slate-500 text-sm mb-6">Add a domain, IP, or CIDR. Sentinel runs all enabled passive modules against it on the hourly cron.</p>
          <form onSubmit={addTarget} className="flex gap-2 max-w-2xl">
            <input
              type="text"
              placeholder="example.com or 192.168.1.0/24"
              className="flex-1 bg-[#111827] border border-slate-700 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-sky-500"
              value={newTarget}
              onChange={e => setNewTarget(e.target.value)}
              disabled={adding}
            />
            <button type="submit" disabled={adding || !newTarget.trim()}
              className="bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-bold px-6 rounded-xl transition">
              Add
            </button>
          </form>
          {error && <div className="mt-3 text-rose-400 text-xs">{error}</div>}
        </div>

        {/* Module health row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <HealthCard
            label="GitHub Sweep"
            primary={`${data?.github?.totalResults ?? 0}`}
            sub={`${data?.github?.queryCount ?? 0} queries · ${data?.github?.proxyCount ?? 0} proxies · ${data?.github?.tokenCount ?? 0} tokens`}
            ok={(data?.github?.totalResults ?? 0) > 0}
            href="/github"
          />
          <HealthCard
            label="Local Network"
            primary={`${data?.network?.hostCount ?? 0}`}
            sub={data?.network?.lastScan ? `last ${new Date(data.network.lastScan).toLocaleTimeString()}` : 'no scans yet'}
            ok={!!data?.network?.lastScan}
            href="/local"
          />
          <HealthCard
            label="Passive Net"
            primary={`${data?.passive?.deviceCount ?? 0}`}
            sub={data?.passive?.isRunning ? 'ARP / mDNS / SSDP listening' : 'idle'}
            ok={!!data?.passive?.isRunning}
            href="/local"
          />
          <HealthCard
            label="OSINT Providers"
            primary={`${enabledProviders}/${totalProviders}`}
            sub={data?.webhookConfigured ? 'webhook configured' : 'webhook off'}
            ok={enabledProviders > 0}
          />
        </div>

        {/* Targets table */}
        <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 bg-black/20 flex items-center justify-between">
            <span className="text-sm font-bold text-white uppercase tracking-widest">Monitored Targets</span>
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{data?.targets?.length ?? 0} total</span>
          </div>
          {data?.targets?.length ? (
            <table className="w-full text-left">
              <thead>
                <tr className="bg-slate-950/50">
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Target</th>
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Modules</th>
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Snapshots</th>
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Recent Diff</th>
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Last Scan</th>
                  <th className="px-6 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest"></th>
                </tr>
              </thead>
              <tbody>
                {data.targets.map(t => {
                  const diff = t.recentDiffs?.web || t.recentDiffs?.osint;
                  return (
                    <tr key={t.id} className="border-t border-slate-800/50 hover:bg-slate-800/20">
                      <td className="px-6 py-4">
                        <div className="text-sm font-bold text-white">{t.value}</div>
                        <div className="text-[10px] text-slate-500 uppercase tracking-widest">{t.kind}</div>
                      </td>
                      <td className="px-6 py-4 text-xs text-slate-400">
                        {Object.entries(t.modules).filter(([, v]) => v).map(([k]) => k).join(' · ')}
                      </td>
                      <td className="px-6 py-4 text-xs text-slate-500 font-mono">
                        web {t.snapshots.web} · osint {t.snapshots.osint} · net {t.snapshots.network}
                      </td>
                      <td className="px-6 py-4 text-xs">
                        {diff ? (
                          <span>
                            <span className="text-emerald-400 font-bold">+{diff.added}</span>
                            <span className="text-slate-500"> · </span>
                            <span className="text-rose-400 font-bold">-{diff.removed}</span>
                            <span className="text-slate-500"> · </span>
                            <span className="text-amber-400 font-bold">~{diff.changed}</span>
                          </span>
                        ) : <span className="text-slate-600">—</span>}
                      </td>
                      <td className="px-6 py-4 text-[10px] text-slate-500 uppercase tracking-widest">
                        {t.lastScannedAt ? new Date(t.lastScannedAt).toLocaleString() : 'never'}
                      </td>
                      <td className="px-6 py-4 flex flex-wrap gap-2">
                        {t.modules.web && (
                          <Link href={`/?target=${encodeURIComponent(t.value)}`} className="text-[10px] font-bold text-sky-400 hover:text-sky-300">Web ↗</Link>
                        )}
                        {t.modules.network && (
                          <Link href={`/local?target=${encodeURIComponent(t.value)}`} className="text-[10px] font-bold text-sky-400 hover:text-sky-300">Net ↗</Link>
                        )}
                        <a href={`/api/export/json?target=${encodeURIComponent(t.value)}`} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-slate-400 hover:text-white">JSON</a>
                        <a href={`/api/export/csv?target=${encodeURIComponent(t.value)}`} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-slate-400 hover:text-white">CSV</a>
                        <button onClick={() => removeTarget(t.id)} className="text-[10px] font-bold text-rose-400 hover:text-rose-300">Remove</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="py-16 text-center text-slate-600 text-xs">No targets yet — add one above to begin monitoring.</div>
          )}
        </div>

        {/* Provider health */}
        <div className="bg-[#0d111a] border border-slate-800 rounded-3xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 bg-black/20">
            <span className="text-sm font-bold text-white uppercase tracking-widest">OSINT Providers</span>
            <p className="text-[10px] text-slate-600 mt-1">All providers are passive. Disabled ones need an API key in env.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-slate-800">
            {data?.osintProviders?.map(p => (
              <div key={p.name} className="bg-[#0d111a] p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-bold text-white">{p.name}</span>
                  <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${p.enabled ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-slate-700/30 text-slate-500 border border-slate-700'}`}>
                    {p.enabled ? 'Active' : 'Off'}
                  </span>
                </div>
                {p.hint && <p className="text-[10px] text-slate-500">{p.hint}</p>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function HealthCard({ label, primary, sub, ok, href }: { label: string; primary: string; sub: string; ok: boolean; href?: string }) {
  const inner = (
    <div className={`bg-[#0d111a] border rounded-2xl p-5 transition ${ok ? 'border-slate-800 hover:border-sky-500/50' : 'border-slate-800/50 opacity-70'}`}>
      <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">{label}</div>
      <div className={`text-3xl font-black ${ok ? 'text-white' : 'text-slate-600'}`}>{primary}</div>
      <div className="text-[10px] text-slate-500 mt-2">{sub}</div>
    </div>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}
