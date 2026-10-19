import { randomUUID } from "node:crypto";
import { SIGNATURE_HEADER, signPayload } from "./signing.js";
import { resolveWebhookUrl, type UrlOptions } from "./url-safety.js";

/** What every delivery's body looks like. */
export type WebhookEvent<T = unknown> = {
  id: string;
  type: string;
  createdAt: string;
  data: T;
};

export function createEvent<T>(type: string, data: T, options: { id?: string; now?: Date } = {}): WebhookEvent<T> {
  return { id: options.id ?? `evt_${randomUUID().replaceAll("-", "")}`, type, createdAt: (options.now ?? new Date()).toISOString(), data };
}

export type DeliveryResult = {
  ok: boolean;
  /** HTTP status, or null when no response came back. */
  status: number | null;
  durationMs: number;
  error: string | null;
  /** The start of the response body, for showing the person what went wrong. */
  responseSnippet: string | null;
};

const SNIPPET_LENGTH = 500;
export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * POSTs one signed event. Never throws: every outcome is a DeliveryResult.
 * Redirects aren't followed (a 3xx counts as a failure), and the URL is
 * re-resolved first so a host can't move to a private address after saving.
 */
export async function deliver(input: {
  url: string;
  secret: string;
  event: WebhookEvent;
  userAgent?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  urlOptions?: UrlOptions;
  lookup?: (host: string) => Promise<Array<{ address: string }>>;
  now?: () => number;
}): Promise<DeliveryResult> {
  const clock = input.now ?? Date.now;
  const started = clock();
  const done = (partial: Omit<DeliveryResult, "durationMs">): DeliveryResult => ({ ...partial, durationMs: Math.max(0, clock() - started) });

  const safe = await resolveWebhookUrl(input.url, { ...input.urlOptions, lookup: input.lookup });
  if (!safe.ok) return done({ ok: false, status: null, error: safe.error, responseSnippet: null });

  const body = JSON.stringify(input.event);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const response = await (input.fetch ?? fetch)(safe.url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": input.userAgent ?? "Noirly-Webhooks/0.1",
        "Noirly-Event": input.event.type,
        "Noirly-Delivery": input.event.id,
        [SIGNATURE_HEADER]: signPayload(input.secret, body),
      },
      body,
    });
    const text = await response.text().catch(() => "");
    const ok = response.status >= 200 && response.status < 300;
    return done({
      ok,
      status: response.status,
      error: ok ? null : response.status >= 300 && response.status < 400 ? "Redirects aren't followed" : `Responded ${response.status}`,
      responseSnippet: text ? text.slice(0, SNIPPET_LENGTH) : null,
    });
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return done({ ok: false, status: null, error: aborted ? "Timed out" : "Couldn't connect", responseSnippet: null });
  } finally {
    clearTimeout(timer);
  }
}
