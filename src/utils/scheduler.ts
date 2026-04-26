/**
 * Hourly scheduler:
 *   1. Cron every minute checks if any per-target work is due (hourly cadence).
 *   2. For each target, runs the modules it has enabled (web/osint/network).
 *   3. After each run, writes a snapshot, diffs it against the previous one,
 *      and fires the webhook if anything new appeared.
 *
 * Existing global GitHub sweep stays — it's not target-scoped.
 */
import cron from 'node-cron';
import { networkScanner } from './networkScanner';
import { githubScanner } from './githubScanner';
import { passiveMonitor } from './arpMonitor';
import { runOsint, OsintFinding } from './osintScanner';
import { targetStore } from './targetStore';
import { saveSnapshot, loadPrevious } from './snapshots';
import { diffById, summarise } from './diffEngine';
import { notify } from './notifier';

let started = false;

export function startScheduler() {
  if (started) return;
  started = true;

  console.log('[CRON] Starting scheduler — passive surveillance loop');

  // Always-on passive listeners
  passiveMonitor.start();

  // Hourly sweeps
  cron.schedule('0 * * * *', () => {
    runHourlyCycle().catch(e => console.error('[CRON cycle]', e));
  });

  // Boot-time fire
  if (!networkScanner.getLatest()) {
    console.log('[CRON] No cached network scan — firing initial run');
    networkScanner.runScan().catch(e => console.error('[CRON network init]', e));
  }
  if (githubScanner.getHistory().length === 0) {
    console.log('[CRON] No cached github results — firing initial run');
    githubScanner.runScan().catch(e => console.error('[CRON github init]', e));
  }
  setTimeout(() => runHourlyCycle().catch(e => console.error('[CRON boot cycle]', e)), 30_000);
}

async function runHourlyCycle() {
  console.log('[CRON] Hourly cycle starting');

  // 1. Global GitHub sweep
  try {
    await githubScanner.runScan();
  } catch (e) {
    console.error('[CRON github]', e);
  }

  // 2. Network scan (uses default target unless we have CIDR targets)
  const targets = targetStore.list();
  const cidrTargets = targets.filter(t => t.kind === 'cidr' && t.modules.network);
  if (cidrTargets.length === 0) {
    await networkScanner.runScan();
  } else {
    for (const t of cidrTargets) {
      const record = await networkScanner.runScan(t.value);
      if (record) {
        await snapshotAndDiff('network', t.value, record.results, x => `${x.id}-${x.feature}`, x => `${x.status}-${x.description}`);
        targetStore.recordScan(t.id);
      }
    }
  }

  // 3. Per-target OSINT
  const domainTargets = targets.filter(t => t.kind === 'domain' && t.modules.osint);
  for (const t of domainTargets) {
    try {
      const findings: OsintFinding[] = [];
      await runOsint(t.value, { emit: f => findings.push(f) });
      await snapshotAndDiff('osint', t.value, findings, x => x.feature, x => `${x.status}-${x.description}`);
      targetStore.recordScan(t.id);
    } catch (e) {
      console.error(`[CRON osint ${t.value}]`, e);
    }
  }

  console.log('[CRON] Hourly cycle complete');
}

async function snapshotAndDiff<T>(
  module: 'web' | 'network' | 'osint',
  target: string,
  payload: T[],
  idOf: (item: T) => string,
  fingerprint: (item: T) => string,
) {
  const previous = loadPrevious<T[]>(module, target);
  saveSnapshot(module, target, payload);
  const diff = diffById<T>(previous?.payload, payload, idOf, fingerprint);
  const summary = summarise(diff);
  if (summary.total > 0) {
    const highlights = [
      ...diff.added.slice(0, 5).map(a => `+ ${describe(a)}`),
      ...diff.removed.slice(0, 3).map(a => `- ${describe(a)}`),
    ];
    await notify({ module, target, ...summary, highlights });
  }
}

function describe(item: unknown): string {
  const x = item as { feature?: string; description?: string; id?: number };
  return x.feature ?? x.description ?? String(x.id ?? '?');
}
