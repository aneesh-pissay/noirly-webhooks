# noirly-webhooks

Signed outgoing webhooks shared by Noirly apps. Published to GitHub Packages as `@aneesh-pissay/webhooks`; apps alias it as `@noirly-dev/webhooks`.

It has no storage of its own. The app keeps its webhooks and delivery log and uses this package to sign, check URLs, deliver and time retries.

## Sending (in an app)

```ts
import { checkWebhookUrl, createEvent, deliver, generateSecret, isRetryable, nextAttemptAt } from "@noirly-dev/webhooks";

const secret = generateSecret(); // show once, store with the webhook
const check = checkWebhookUrl(url); // when saving; deliver() also re-resolves DNS each time
const event = createEvent("task.created", task);
const result = await deliver({ url, secret, event }); // never throws
if (!result.ok && isRetryable(result)) retryAt = nextAttemptAt(attemptsMade);
```

- Only `https://` URLs on public addresses. Hosts that resolve to loopback, private, link-local or metadata addresses are refused, at save time and again before every delivery. `allowInsecureLocalhost` exists for local development.
- Redirects aren't followed. Requests time out after 10 seconds.
- Retries: 1 min, 5 min, 30 min, 2 h, 6 h (with up to 10% jitter), then give up. A `410 Gone` isn't retried.

## Receiving

Every request is a `POST` with a JSON body `{ id, type, createdAt, data }` and these headers:

| Header | Value |
| --- | --- |
| `Noirly-Event` | The event type, e.g. `task.updated` |
| `Noirly-Delivery` | The event id; the same on retries, so use it to ignore repeats |
| `Noirly-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">` with your signing secret |

Check the signature on the raw body before parsing it:

```ts
import { verifySignature } from "@noirly-dev/webhooks";

const raw = await request.text();
if (!verifySignature(process.env.FLOW_WEBHOOK_SECRET!, request.headers.get("Noirly-Signature"), raw)) {
  return new Response("bad signature", { status: 401 });
}
const event = JSON.parse(raw);
```

Without the package: compute `HMAC-SHA256(secret, t + "." + rawBody)` as hex, compare it to `v1` in constant time, and reject timestamps more than 5 minutes off.

Reply with any 2xx quickly; do slow work after responding.

## Develop

```bash
pnpm install
pnpm test
pnpm build
```

Publishing runs from `.github/workflows/publish.yml` when a GitHub release is published.
