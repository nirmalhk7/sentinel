/**
 * Multi-target persistence. Targets carry metadata about which modules apply
 * (web/network/github-mention/osint) and when they were last scanned.
 */
import fs from 'fs';
import path from 'path';
import { DATA_DIR, ensureDataDir } from './paths';

export type TargetKind = 'domain' | 'cidr' | 'ip';

export interface Target {
  id: string; // stable hash-ish key derived from value
  value: string; // domain, cidr or ip
  kind: TargetKind;
  label?: string;
  modules: {
    web: boolean;
    network: boolean;
    osint: boolean;
  };
  addedAt: string;
  lastScannedAt?: string;
  lastRiskScore?: number;
}

const FILE = path.join(DATA_DIR, 'targets.json');

function load(): Target[] {
  if (!fs.existsSync(FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch {
    return [];
  }
}

function persist(list: Target[]) {
  ensureDataDir();
  fs.writeFileSync(FILE, JSON.stringify(list, null, 2));
}

function inferKind(value: string): TargetKind {
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(value)) return 'cidr';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return 'ip';
  return 'domain';
}

function makeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._/-]/g, '_');
}

export const targetStore = {
  list(): Target[] {
    return load();
  },

  get(id: string): Target | undefined {
    return load().find(t => t.id === id);
  },

  add(value: string, opts?: { label?: string; modules?: Partial<Target['modules']> }): Target {
    const v = value.trim();
    if (!v) throw new Error('Empty target');
    const id = makeId(v);
    const list = load();
    const existing = list.find(t => t.id === id);
    if (existing) return existing;
    const kind = inferKind(v);
    const modules = {
      web: kind === 'domain',
      network: kind === 'cidr' || kind === 'ip',
      osint: true,
      ...(opts?.modules ?? {}),
    };
    const target: Target = {
      id,
      value: v,
      kind,
      label: opts?.label,
      modules,
      addedAt: new Date().toISOString(),
    };
    list.push(target);
    persist(list);
    return target;
  },

  remove(id: string): boolean {
    const list = load();
    const next = list.filter(t => t.id !== id);
    if (next.length === list.length) return false;
    persist(next);
    return true;
  },

  update(id: string, patch: Partial<Omit<Target, 'id' | 'value' | 'kind' | 'addedAt'>>): Target | undefined {
    const list = load();
    const idx = list.findIndex(t => t.id === id);
    if (idx < 0) return undefined;
    list[idx] = { ...list[idx], ...patch };
    persist(list);
    return list[idx];
  },

  recordScan(id: string, riskScore?: number): void {
    this.update(id, {
      lastScannedAt: new Date().toISOString(),
      ...(typeof riskScore === 'number' ? { lastRiskScore: riskScore } : {}),
    });
  },
};
