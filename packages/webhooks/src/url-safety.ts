import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

export type UrlCheck = { ok: true; url: URL } | { ok: false; error: string };

export type UrlOptions = {
  /** Allow http:// to localhost and 127.0.0.1, for local development only. */
  allowInsecureLocalhost?: boolean;
};

const LOCAL_NAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function ipv4Parts(ip: string) {
  return ip.split(".").map(Number);
}

/** Loopback, private, link-local, shared, multicast and other addresses a webhook must not reach. */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const [a = 0, b = 0] = ipv4Parts(ip);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) // carrier-grade NAT
      || (a === 169 && b === 254) // link-local, cloud metadata
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0) // 192.0.0.0/24 and 192.0.2.0/24
      || (a === 198 && (b === 18 || b === 19)); // benchmarking
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPrivateAddress(mapped[1]!);
    return lower === "::" || lower === "::1"
      || lower.startsWith("fc") || lower.startsWith("fd") // unique local
      || /^fe[89ab]/.test(lower) // link-local
      || lower.startsWith("ff"); // multicast
  }
  return true;
}

/** Shape checks only: https (or local http when allowed), no credentials, a public-looking host. */
export function checkWebhookUrl(raw: string, options: UrlOptions = {}): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "Enter a full URL, like https://example.com/hooks" };
  }
  const local = LOCAL_NAMES.has(url.hostname);
  if (local && options.allowInsecureLocalhost && (url.protocol === "http:" || url.protocol === "https:")) return { ok: true, url };
  if (url.protocol !== "https:") return { ok: false, error: "Webhook URLs must use https" };
  if (url.username || url.password) return { ok: false, error: "Leave credentials out of the URL" };
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (local || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    return { ok: false, error: "Webhook URLs must be reachable on the public internet" };
  }
  if (isIP(host) && isPrivateAddress(host)) return { ok: false, error: "Webhook URLs must be reachable on the public internet" };
  return { ok: true, url };
}

type Lookup = (host: string) => Promise<Array<{ address: string }>>;

const defaultLookup: Lookup = (host) => dnsLookup(host, { all: true, verbatim: true });

/**
 * The shape checks, then every address the host resolves to must be public.
 * Run it right before each delivery as well as when saving the URL.
 */
export async function resolveWebhookUrl(raw: string, options: UrlOptions & { lookup?: Lookup } = {}): Promise<UrlCheck> {
  const shape = checkWebhookUrl(raw, options);
  if (!shape.ok) return shape;
  const host = shape.url.hostname.replace(/^\[|\]$/g, "");
  if (LOCAL_NAMES.has(shape.url.hostname) && options.allowInsecureLocalhost) return shape;
  if (isIP(host)) return shape;
  let addresses: Array<{ address: string }>;
  try {
    addresses = await (options.lookup ?? defaultLookup)(host);
  } catch {
    return { ok: false, error: `Couldn't find ${host}` };
  }
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) {
    return { ok: false, error: "Webhook URLs must be reachable on the public internet" };
  }
  return shape;
}
