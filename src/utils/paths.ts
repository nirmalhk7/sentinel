import fs from 'fs';
import path from 'path';

export const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');

let ensured = false;
export function ensureDataDir() {
  if (ensured) return;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  ensured = true;
}
