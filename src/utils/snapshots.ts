/**
 * Per-module timestamped snapshots — used to detect what changed between scans.
 *
 * Layout: <DATA_DIR>/snapshots/<module>/<target>/<ts>.json
 * Target is sanitised; module is one of 'web' | 'network' | 'github' | 'osint'.
 */
import fs from 'fs';
import path from 'path';
import { DATA_DIR, ensureDataDir } from './paths';

export type SnapshotModule = 'web' | 'network' | 'github' | 'osint';

export interface Snapshot<T = unknown> {
  module: SnapshotModule;
  target: string;
  takenAt: string;
  payload: T;
}

const MAX_SNAPSHOTS_PER_TARGET = 30;

function moduleDir(module: SnapshotModule): string {
  return path.join(DATA_DIR, 'snapshots', module);
}

function safeKey(target: string): string {
  return target.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120) || '_';
}

function targetDir(module: SnapshotModule, target: string): string {
  return path.join(moduleDir(module), safeKey(target));
}

export function saveSnapshot<T>(module: SnapshotModule, target: string, payload: T): Snapshot<T> {
  ensureDataDir();
  const dir = targetDir(module, target);
  fs.mkdirSync(dir, { recursive: true });
  const snap: Snapshot<T> = {
    module,
    target,
    takenAt: new Date().toISOString(),
    payload,
  };
  const filename = `${Date.now()}.json`;
  fs.writeFileSync(path.join(dir, filename), JSON.stringify(snap, null, 2));
  trim(dir);
  return snap;
}

function trim(dir: string) {
  const files = fs
    .readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();
  for (const f of files.slice(MAX_SNAPSHOTS_PER_TARGET)) {
    try {
      fs.unlinkSync(path.join(dir, f));
    } catch {}
  }
}

export function listSnapshots(module: SnapshotModule, target: string): string[] {
  const dir = targetDir(module, target);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();
}

export function loadSnapshot<T = unknown>(
  module: SnapshotModule,
  target: string,
  filename: string,
): Snapshot<T> | null {
  const file = path.join(targetDir(module, target), filename);
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as Snapshot<T>;
  } catch {
    return null;
  }
}

export function loadLatest<T = unknown>(module: SnapshotModule, target: string): Snapshot<T> | null {
  const files = listSnapshots(module, target);
  return files.length > 0 ? loadSnapshot<T>(module, target, files[0]) : null;
}

export function loadPrevious<T = unknown>(module: SnapshotModule, target: string): Snapshot<T> | null {
  const files = listSnapshots(module, target);
  return files.length > 1 ? loadSnapshot<T>(module, target, files[1]) : null;
}
