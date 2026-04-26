/**
 * Aggregated state for the dashboard — pulls data from every module so the UI
 * doesn't need to make a dozen separate calls.
 */
import type { NextApiRequest, NextApiResponse } from 'next';
import { targetStore } from '@/utils/targetStore';
import { networkScanner } from '@/utils/networkScanner';
import { githubScanner } from '@/utils/githubScanner';
import { passiveMonitor } from '@/utils/arpMonitor';
import { listProviders } from '@/utils/osintScanner';
import { listSnapshots, loadLatest, loadPrevious } from '@/utils/snapshots';
import { diffById, summarise } from '@/utils/diffEngine';
import { isConfigured as webhookConfigured } from '@/utils/notifier';

interface ScanLike { id: number; status: string; feature: string }

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  const targets = targetStore.list();
  const enriched = targets.map(t => {
    const recentDiffs: Record<string, ReturnType<typeof summarise>> = {};

    if (t.modules.web) {
      const a = loadLatest<ScanLike[]>('web', t.value);
      const b = loadPrevious<ScanLike[]>('web', t.value);
      if (a) {
        const diff = diffById(b?.payload, a.payload, x => `${x.id}`);
        recentDiffs.web = summarise(diff);
      }
    }
    if (t.modules.osint) {
      const a = loadLatest<ScanLike[]>('osint', t.value);
      const b = loadPrevious<ScanLike[]>('osint', t.value);
      if (a) {
        const diff = diffById(b?.payload, a.payload, x => `${x.feature}`);
        recentDiffs.osint = summarise(diff);
      }
    }

    return {
      ...t,
      snapshots: {
        web: listSnapshots('web', t.value).length,
        osint: listSnapshots('osint', t.value).length,
        network: listSnapshots('network', t.value).length,
      },
      recentDiffs,
    };
  });

  return res.status(200).json({
    targets: enriched,
    network: {
      lastScan: networkScanner.getLastScanTime(),
      isRunning: networkScanner.isRunning(),
      hostCount: networkScanner.getLatest()?.hostCount ?? 0,
    },
    github: githubScanner.health(),
    passive: {
      isRunning: passiveMonitor.isRunning(),
      deviceCount: passiveMonitor.list().length,
    },
    osintProviders: listProviders(),
    webhookConfigured: webhookConfigured(),
  });
}
