# voidnote-sdk

Official TypeScript/JavaScript SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes and live encrypted streams.

**v0.4.1** · Node 18+, Deno, Bun, Cloudflare Workers, browsers · zero-knowledge v1 API

## Install

```bash
npm install voidnote-sdk
# or
pnpm add voidnote-sdk
# or
bun add voidnote-sdk
```

## Quick start

```typescript
import { create, read, peek } from "voidnote-sdk";

// Create a note — content is encrypted locally, server never sees plaintext
const result = await create("my secret value", {
  apiKey: "vn_...",
  maxViews: 1,       // destroy after this many reads (1–100)
  expiresIn: 1,      // hours until expiry (1–720)
});
console.log(result.url);    // https://voidnote.net/n/<tokenId>#<secret>
console.log(result.token);  // 32-char tokenId
```

## API

### `create(content, options) → Promise<CreateResult>`

Encrypt content locally and store the ciphertext. Requires an API key from your [dashboard](https://voidnote.net/dashboard).

```typescript
import { create } from "voidnote-sdk";

const result = await create("deploy key: abc123", {
  apiKey: "vn_...",
  maxViews: 3,
  expiresIn: 6,  // 6 hours
});
console.log(result.url);        // full shareable URL — includes #secret
console.log(result.token);      // 32-char tokenId only
console.log(result.expiresAt);
```

### `read(url) → Promise<ReadResult>`

Fetch and decrypt a note. Consumes one view. Accepts both v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```typescript
import { read } from "voidnote-sdk";

const note = await read("https://voidnote.net/n/<tokenId>#<secret>");
console.log(note.content);          // decrypted plaintext
console.log(note.viewsRemaining);   // views left after this read
console.log(note.destroyed);        // true if this was the last view
```

### `peek(url) → Promise<PeekResult>`

Check metadata without consuming a view.

```typescript
import { peek } from "voidnote-sdk";

const meta = await peek("https://voidnote.net/n/<tokenId>#<secret>");
console.log(meta.exists);
console.log(meta.viewsRemaining);
console.log(meta.expiresAt);
```

### Void Streams

Live encrypted real-time channels. Messages are encrypted before leaving your machine.

```typescript
import { createStream, watch } from "voidnote-sdk";

// Create a channel
const stream = await createStream({ apiKey: "vn_...", title: "Deploy #42" });
console.log(stream.url);  // share this URL with watchers

// Write messages (write and close are authenticated with the same API key)
await stream.write("Starting deployment...");
await stream.write("Build complete.");
await stream.close();  // self-destructs all content

// Watch a stream — async iterator of decrypted messages
for await (const message of watch("https://voidnote.net/stream/<token>")) {
  console.log(message);
}

// Password-protected stream
for await (const message of watch(url, undefined, { password: "hunter2" })) {
  console.log(message);
}
```

### Crypto payments

```typescript
import { createCryptoOrder, submitCryptoPayment } from "voidnote-sdk";

// Create a payment order
const order = await createCryptoOrder({
  apiKey: "vn_...",
  bundleId: "starter",  // "test" | "starter" | "standard" | "pro"
  chain: "polygon",
  token: "USDT",
});
console.log(`Send ${order.amount} ${order.token} to ${order.toAddress}`);

// After sending, submit the tx hash
const result = await submitCryptoPayment({
  apiKey: "vn_...",
  orderId: order.orderId,
  txHash: "0x...",
});
console.log(`+${result.creditsAdded} credits`);
```

## Security model

```
server generates  tokenId  (32-char hex — stored as lookup key)
client generates  secret   (32-char hex — NEVER sent to server)

key        = SHA-256(hex_decode(secret))
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Environments

Works in Node.js 18+, Deno, Bun, Cloudflare Workers, and any environment with the Web Crypto API and `fetch`.

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-js)
