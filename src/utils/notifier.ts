/**
 * Webhook notifier — POSTs new findings to ALERT_WEBHOOK_URL.
 * Gracefully no-ops when the env var is unset.
 *
 * Compatible with Slack-incoming-webhook style payloads (text + attachments)
 * and generic JSON receivers (n8n, Discord via "content", etc.).
 */
import axios from 'axios';

interface NotifyPayload {
  module: 'web' | 'network' | 'github' | 'osint';
  target: string;
  added: number;
  removed: number;
  changed: number;
  highlights: string[]; // human-readable bullets, max ~10
}

export async function notify(payload: NotifyPayload): Promise<void> {
  const url = process.env.ALERT_WEBHOOK_URL;
  if (!url) return;
  if (payload.added + payload.removed + payload.changed === 0) return;

  const summary = `[Sentinel] ${payload.module}/${payload.target}: +${payload.added} new, -${payload.removed} gone, ~${payload.changed} changed`;
  const body = {
    text: summary,
    content: summary, // discord
    module: payload.module,
    target: payload.target,
    added: payload.added,
    removed: payload.removed,
    changed: payload.changed,
    highlights: payload.highlights,
    timestamp: new Date().toISOString(),
  };

  try {
    await axios.post(url, body, { timeout: 8000 });
    console.log(`[NOTIFY] Webhook fired: ${summary}`);
  } catch (e) {
    const err = e as Error;
    console.error(`[NOTIFY] Webhook failed: ${err.message}`);
  }
}

export function isConfigured(): boolean {
  return !!process.env.ALERT_WEBHOOK_URL;
}
