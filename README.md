# voidnote-sdk

Official TypeScript/JavaScript SDK for [VoidNote](https://voidnote.net): zero-knowledge self-destructing notes and live encrypted streams.

**v0.5.0** · Node 18+, Deno, Bun, Cloudflare Workers, browsers · no account needed for notes

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
import { create, read } from "voidnote-sdk";

// No account or API key needed. Content is encrypted locally; the server never sees it.
const note = await create("my secret value");
console.log(note.url);    // https://voidnote.net/n/<tokenId>#<secret>

const opened = await read(note.url);
console.log(opened.content);
```

## API

### `create(content, options?) → Promise<CreateResult>`

Encrypt content locally and store the ciphertext.

```typescript
import { create } from "voidnote-sdk";

const result = await create("deploy key: abc123", {
  maxViews: 3,      // default 1
  expiresIn: 6,     // hours, default 1
});
console.log(result.url);        // full shareable URL, includes #secret
console.log(result.token);      // 32-char tokenId only
console.log(result.expiresAt, result.viewLimit, result.kdf);
```

Without an API key the note is anonymous: up to 168 hours (7 days) and 10 views, rate-limited per IP. An API key from a free account raises that to 720 hours and 100 views:

```typescript
await create("deploy key: abc123", { apiKey: "vn_...", maxViews: 50, expiresIn: 720 });
```

Add a password and the reader needs it as well as the link. The key is then PBKDF2-HMAC-SHA256 (600,000 iterations) of the password, salted with the link's secret:

```typescript
const guarded = await create("db password: hunter2", { password: "correct horse" });
// share guarded.url and the password through different channels
```

### `read(url, options?) → Promise<ReadResult>`

Fetch and decrypt a note. Consumes one view. Accepts v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```typescript
import { read } from "voidnote-sdk";

const note = await read("https://voidnote.net/n/<tokenId>#<secret>");
console.log(note.content);          // decrypted plaintext
console.log(note.viewsRemaining);   // views left after this read
console.log(note.destroyed);        // true if this was the last view

// A note created with a password
const guarded = await read(url, { password: "correct horse" });
```

Before using a view, `read` checks the note's metadata. A missing note, a password note read without a password, or an unknown key derivation throws without touching the view. A wrong password can only be detected after decrypting, so it does use the view.

### `peek(url) → Promise<PeekResult>`

Check metadata without consuming a view. `kdf` is `"pbkdf2-sha256-600k"` when the note needs a password.

```typescript
import { peek } from "voidnote-sdk";

const meta = await peek("https://voidnote.net/n/<tokenId>#<secret>");
console.log(meta.exists, meta.viewsRemaining, meta.expiresAt, meta.kdf);
```

### Errors

Every failure is a `VoidNoteError` with a `code`:

| code | meaning |
|------|---------|
| `http` | the server refused; `status` and the server's message, plus `retryAfter` (seconds) on 429 |
| `not_found` | the note doesn't exist, expired, or its views are used up |
| `password_required` | the note needs a password; no view was used |
| `unsupported_kdf` | the note uses a key derivation this version can't do; no view was used |
| `decryption_failed` | wrong password or a damaged link; the view was used |

```typescript
import { create, VoidNoteError } from "voidnote-sdk";

try {
  await create("x");
} catch (e) {
  if (e instanceof VoidNoteError && e.status === 429) {
    console.log(`rate limited, retry in ${e.retryAfter}s: ${e.message}`);
  }
}
```

### Void Streams

Live encrypted real-time channels. Creating one needs an API key from a free account; watching doesn't.

```typescript
import { createStream, watch } from "voidnote-sdk";

// Create a channel
const stream = await createStream({ apiKey: "vn_...", title: "Deploy #42" });
console.log(stream.url);  // share this URL with watchers

// Write messages (write and close are authenticated with the same API key)
await stream.write("Starting deployment...");
await stream.write("Build complete.");
await stream.close();  // self-destructs all content

// Watch a stream: async iterator of decrypted messages
for await (const message of watch("https://voidnote.net/stream/<token>")) {
  console.log(message);
}

// Password-protected stream
for await (const message of watch(url, undefined, { password: "hunter2" })) {
  console.log(message);
}
```

## Security model

```
server generates  tokenId  (32-char hex, stored as lookup key)
client generates  secret   (32-char hex, NEVER sent to server)

key        = SHA-256(hex_decode(secret))                                  kdf "sha256"
key        = PBKDF2-HMAC-SHA256(password, hex_decode(secret), 600000)     kdf "pbkdf2-sha256-600k"
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Tests

```bash
npm test                 # unit tests, mocked network
node test/live.mjs       # creates real anonymous notes on voidnote.net
```

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-js)
