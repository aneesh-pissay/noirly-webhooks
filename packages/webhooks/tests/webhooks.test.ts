import { describe, expect, it, vi } from "vitest";
import {
  MAX_ATTEMPTS, checkWebhookUrl, createEvent, deliver, generateSecret, isPrivateAddress, isRetryable,
  nextAttemptAt, resolveWebhookUrl, signPayload, verifySignature,
} from "../src/index.js";

const publicLookup = async () => [{ address: "93.184.216.34" }];

describe("signing", () => {
  const secret = generateSecret();
  const body = JSON.stringify({ hello: "world" });
  const now = new Date("2026-10-19T12:00:00Z");

  it("makes secrets with a recognisable prefix", () => {
    expect(secret).toMatch(/^whsec_[\w-]{32}$/);
    expect(generateSecret()).not.toBe(secret);
  });

  it("verifies its own signature, and nothing else", () => {
    const header = signPayload(secret, body, now);
    expect(header).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifySignature(secret, header, body, { now })).toBe(true);
    expect(verifySignature(secret, header, `${body} `, { now })).toBe(false);
    expect(verifySignature(generateSecret(), header, body, { now })).toBe(false);
    expect(verifySignature(secret, header.replace(/v1=./, "v1=0"), body, { now })).toBe(false);
    expect(verifySignature(secret, null, body, { now })).toBe(false);
    expect(verifySignature(secret, "t=abc,v1=xyz", body, { now })).toBe(false);
  });

  it("refuses old or future timestamps", () => {
    const header = signPayload(secret, body, now);
    expect(verifySignature(secret, header, body, { now: new Date(now.getTime() + 299_000) })).toBe(true);
    expect(verifySignature(secret, header, body, { now: new Date(now.getTime() + 301_000) })).toBe(false);
    expect(verifySignature(secret, header, body, { now: new Date(now.getTime() - 301_000) })).toBe(false);
  });
});

describe("url safety", () => {
  it("knows private addresses", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["93.184.216.34", "8.8.8.8", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8"]) {
      expect(isPrivateAddress(ip), ip).toBe(false);
    }
  });

  it("checks the URL's shape", () => {
    expect(checkWebhookUrl("https://hooks.example.com/flow").ok).toBe(true);
    expect(checkWebhookUrl("http://hooks.example.com/flow")).toMatchObject({ ok: false, error: "Webhook URLs must use https" });
    expect(checkWebhookUrl("not a url").ok).toBe(false);
    expect(checkWebhookUrl("https://user:pass@example.com").ok).toBe(false);
    expect(checkWebhookUrl("https://localhost/hook").ok).toBe(false);
    expect(checkWebhookUrl("https://printer.local/hook").ok).toBe(false);
    expect(checkWebhookUrl("https://10.0.0.5/hook").ok).toBe(false);
    expect(checkWebhookUrl("https://[::1]/hook").ok).toBe(false);
    expect(checkWebhookUrl("http://localhost:4000/hook", { allowInsecureLocalhost: true }).ok).toBe(true);
  });

  it("refuses hosts that resolve to private addresses", async () => {
    expect((await resolveWebhookUrl("https://hooks.example.com", { lookup: publicLookup })).ok).toBe(true);
    const sneaky = async () => [{ address: "93.184.216.34" }, { address: "10.0.0.1" }];
    expect((await resolveWebhookUrl("https://rebind.example.com", { lookup: sneaky })).ok).toBe(false);
    const missing = async () => { throw new Error("ENOTFOUND"); };
    expect(await resolveWebhookUrl("https://nope.example.com", { lookup: missing })).toMatchObject({ ok: false, error: "Couldn't find nope.example.com" });
  });
});

describe("deliver", () => {
  const secret = generateSecret();
  const event = createEvent("task.created", { id: "t1" }, { id: "evt_1", now: new Date("2026-10-19T12:00:00Z") });

  it("posts a signed event and reports success", async () => {
    const fetch = vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      const headers = init!.headers as Record<string, string>;
      expect(headers["Noirly-Event"]).toBe("task.created");
      expect(headers["Noirly-Delivery"]).toBe("evt_1");
      expect(verifySignature(secret, headers["Noirly-Signature"], String(init!.body))).toBe(true);
      expect(init!.redirect).toBe("manual");
      return new Response("thanks", { status: 202 });
    });
    const result = await deliver({ url: "https://hooks.example.com", secret, event, fetch, lookup: publicLookup });
    expect(result).toMatchObject({ ok: true, status: 202, error: null, responseSnippet: "thanks" });
    expect(JSON.parse(String(fetch.mock.calls[0]![1]!.body))).toEqual(event);
  });

  it("reports failures without throwing", async () => {
    const status = (code: number) => vi.fn(async () => new Response("", { status: code }));
    expect(await deliver({ url: "https://hooks.example.com", secret, event, fetch: status(500), lookup: publicLookup }))
      .toMatchObject({ ok: false, status: 500, error: "Responded 500" });
    expect(await deliver({ url: "https://hooks.example.com", secret, event, fetch: status(302), lookup: publicLookup }))
      .toMatchObject({ ok: false, status: 302, error: "Redirects aren't followed" });
    const down = vi.fn(async () => { throw new TypeError("fetch failed"); });
    expect(await deliver({ url: "https://hooks.example.com", secret, event, fetch: down, lookup: publicLookup }))
      .toMatchObject({ ok: false, status: null, error: "Couldn't connect" });
    const never = vi.fn(fetch);
    expect(await deliver({ url: "https://10.0.0.1/hook", secret, event, fetch: never })).toMatchObject({ ok: false, status: null });
    expect(never).not.toHaveBeenCalled();
  });

  it("times out slow receivers", async () => {
    const slow = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init!.signal!.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
    }));
    expect(await deliver({ url: "https://hooks.example.com", secret, event, fetch: slow, lookup: publicLookup, timeoutMs: 20 }))
      .toMatchObject({ ok: false, error: "Timed out" });
  });
});

describe("retries", () => {
  it("backs off, then gives up", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    expect(nextAttemptAt(1, now, () => 0)).toEqual(new Date("2026-10-19T12:01:00Z"));
    expect(nextAttemptAt(2, now, () => 0)).toEqual(new Date("2026-10-19T12:05:00Z"));
    expect(nextAttemptAt(5, now, () => 0)).toEqual(new Date("2026-10-19T18:00:00Z"));
    expect(nextAttemptAt(MAX_ATTEMPTS, now)).toBeNull();
    const jittered = nextAttemptAt(1, now, () => 1)!.getTime() - now.getTime();
    expect(jittered).toBe(66_000);
  });

  it("doesn't retry a 410", () => {
    expect(isRetryable({ ok: false, status: 500 })).toBe(true);
    expect(isRetryable({ ok: false, status: null })).toBe(true);
    expect(isRetryable({ ok: false, status: 410 })).toBe(false);
    expect(isRetryable({ ok: true, status: 200 })).toBe(false);
  });
});
