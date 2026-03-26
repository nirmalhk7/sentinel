import fs from 'fs';
import path from 'path';

const HISTORY_FILE = path.join(process.cwd(), '.scan_history.json');

export interface ScanHistory {
  date: string; // ISO Date YYYY-MM-DD
  totalScans: number;
  targets: Record<string, number>; // target -> count
}

export class ScanLimiter {
  private static readonly MAX_SCANS_PER_DAY = 50;
  private static readonly MAX_SCANS_PER_TARGET_PER_DAY = 5;

  private static loadHistory(): ScanHistory {
    const today = new Date().toISOString().split('T')[0];
    if (fs.existsSync(HISTORY_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf-8'));
        if (data.date === today) {
          return data;
        }
      } catch (e) {
        console.error('Failed to load scan history:', e);
      }
    }
    return { date: today, totalScans: 0, targets: {} };
  }

  private static saveHistory(history: ScanHistory) {
    try {
      fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
    } catch (e) {
      console.error('Failed to save scan history:', e);
    }
  }

  /**
   * Checks if a scan is allowed and records it.
   * @returns true if allowed, false if over limit.
   */
  static checkAndRecord(target: string): { allowed: boolean; reason?: string } {
    const history = this.loadHistory();

    if (history.totalScans >= this.MAX_SCANS_PER_DAY) {
      return { allowed: false, reason: `Daily limit reached (${this.MAX_SCANS_PER_DAY} scans).` };
    }

    const host = target.replace(/^https?:\/\//, '').split('/')[0];
    const targetCount = history.targets[host] || 0;

    if (targetCount >= this.MAX_SCANS_PER_TARGET_PER_DAY) {
      return { allowed: false, reason: `Target limit reached for ${host} (${this.MAX_SCANS_PER_TARGET_PER_DAY} scans per day).` };
    }

    // Update history
    history.totalScans += 1;
    history.targets[host] = targetCount + 1;
    this.saveHistory(history);

    return { allowed: true };
  }
}
