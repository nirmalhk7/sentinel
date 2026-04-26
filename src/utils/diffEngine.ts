/**
 * Snapshot comparison — given an "id" extractor, returns added / removed / changed
 * sets between two snapshot payloads.
 */

export interface Diff<T> {
  added: T[];
  removed: T[];
  changed: { before: T; after: T }[];
  unchangedCount: number;
}

export function diffById<T>(
  before: T[] | null | undefined,
  after: T[] | null | undefined,
  idOf: (item: T) => string,
  fingerprint?: (item: T) => string,
): Diff<T> {
  const beforeMap = new Map<string, T>();
  const afterMap = new Map<string, T>();
  for (const b of before ?? []) beforeMap.set(idOf(b), b);
  for (const a of after ?? []) afterMap.set(idOf(a), a);

  const added: T[] = [];
  const removed: T[] = [];
  const changed: { before: T; after: T }[] = [];
  let unchanged = 0;

  for (const [id, a] of afterMap) {
    const b = beforeMap.get(id);
    if (!b) {
      added.push(a);
      continue;
    }
    if (fingerprint) {
      if (fingerprint(b) !== fingerprint(a)) {
        changed.push({ before: b, after: a });
      } else {
        unchanged += 1;
      }
    } else {
      unchanged += 1;
    }
  }
  for (const [id, b] of beforeMap) {
    if (!afterMap.has(id)) removed.push(b);
  }

  return { added, removed, changed, unchangedCount: unchanged };
}

export interface DiffSummary {
  added: number;
  removed: number;
  changed: number;
  total: number;
}

export function summarise<T>(diff: Diff<T>): DiffSummary {
  return {
    added: diff.added.length,
    removed: diff.removed.length,
    changed: diff.changed.length,
    total: diff.added.length + diff.removed.length + diff.changed.length,
  };
}
