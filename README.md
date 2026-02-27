# voidnote

Official TypeScript/JavaScript SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes.

## Install

```bash
npm install voidnote-sdk
```

## Usage

### Read a note

```typescript
import * as voidnote from "voidnote";

const result = await voidnote.read("https://voidnote.net/note/abc123...");
console.log(result.content);   // decrypted content
console.log(result.destroyed); // true if view limit was reached
```

### Create a note (requires API key)

```typescript
import * as voidnote from "voidnote";

const result = await voidnote.create("my secret value", {
  apiKey: "vn_...",
  maxViews: 1,
  title: "Deploy key",
});
console.log(result.url); // share this link
```

## Environments

Works in Node.js 18+, Deno, Bun, Cloudflare Workers, and modern browsers (anything with Web Crypto API + fetch).

## Links

- [voidnote.net](https://voidnote.net)
- [How it works](https://voidnote.net/how-it-works)
- [GitHub](https://github.com/quantum-encoding/voidnote-js)
