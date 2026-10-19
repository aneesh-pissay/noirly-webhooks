import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** The header a receiver checks: `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">`. */
export const SIGNATURE_HEADER = "Noirly-Signature";

/** How far a signature's timestamp may drift from the receiver's clock. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** A new signing secret, shown to the person once and kept by the sending app. */
export function generateSecret(): string {
  return `whsec_${randomBytes(24).toString("base64url")}`;
}

function digest(secret: string, timestamp: number, body: string) {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

/** The signature header value for `body`, sent at `now`. */
export function signPayload(secret: string, body: string, now: Date = new Date()): string {
  const timestamp = Math.floor(now.getTime() / 1000);
  return `t=${timestamp},v1=${digest(secret, timestamp, body)}`;
}

/**
 * For receivers: true when `header` signs exactly `body` with `secret`, within
 * the tolerance. Pass the raw request body, before any JSON parsing.
 */
export function verifySignature(
  secret: string,
  header: string | null | undefined,
  body: string,
  options: { toleranceSeconds?: number; now?: Date } = {},
): boolean {
  if (!header) return false;
  const parts = new Map(header.split(",").map((part) => {
    const at = part.indexOf("=");
    return [part.slice(0, at).trim(), part.slice(at + 1).trim()] as const;
  }));
  const timestamp = Number(parts.get("t"));
  const given = parts.get("v1");
  if (!Number.isInteger(timestamp) || !given || !/^[0-9a-f]{64}$/.test(given)) return false;
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  if (Math.abs(now - timestamp) > (options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS)) return false;
  const expected = Buffer.from(digest(secret, timestamp, body), "hex");
  return timingSafeEqual(expected, Buffer.from(given, "hex"));
}
