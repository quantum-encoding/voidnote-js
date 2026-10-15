/**
 * VoidNote SDK — TypeScript/Node.js
 *
 * npm install voidnote-sdk
 *
 * Works in Node.js 18+, Deno, Bun, Cloudflare Workers, and modern browsers
 * (anything with Web Crypto API + fetch).
 */

export interface ReadResult {
  content: string;
  title: string | null;
  viewCount: number;
  maxViews: number;
  destroyed: boolean;
  viewsRemaining?: number; // v1 URLs only
}

export interface CreateOptions {
  apiKey: string;
  maxViews?: number;                              // 1–100, default 1
  expiresIn?: 1 | 6 | 24 | 72 | 168 | 720;      // hours, default 1
}

export interface CreateResult {
  url: string;      // full shareable link — includes #secret fragment for v1 notes
  token: string;    // 32-char tokenId
  expiresAt: string;
}

export interface PeekResult {
  exists: boolean;
  type?: string;
  createdAt?: string;
  expiresAt?: string;
  viewLimit?: number;
  viewsRemaining?: number;
}

const DEFAULT_BASE = "https://voidnote.net";

// --- helpers ---

function bufToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string) {
  const ab = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(ab);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function deriveKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  const keyMat = await crypto.subtle.digest("SHA-256", hexToBytes(secret).buffer as ArrayBuffer);
  return crypto.subtle.importKey("raw", keyMat, { name: "AES-GCM", length: 256 }, false, usage);
}

async function encryptContent(
  content: string,
  secret: string,
): Promise<{ encrypted: string; iv: string }> {
  const key = await deriveKey(secret, ["encrypt"]);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(content),
  );
  return { encrypted: bufToHex(new Uint8Array(ciphertext)), iv: bufToHex(iv) };
}

async function decryptContent(encHex: string, ivHex: string, secret: string): Promise<string> {
  const key = await deriveKey(secret, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(ivHex) },
    key,
    hexToBytes(encHex),
  );
  return new TextDecoder().decode(plain);
}

type ParsedUrl =
  | { type: "v1"; tokenId: string; secret: string }
  | { type: "legacy"; fullToken: string };

function parseNoteUrl(input: string): ParsedUrl {
  // v1 format: .../n/{32-hex}#{32-hex}
  const hashIdx = input.indexOf("#");
  if (hashIdx !== -1) {
    const secret = input.slice(hashIdx + 1);
    const pathPart = input.slice(0, hashIdx).replace(/\/$/, "");
    const tokenId = pathPart.split("/").pop() ?? "";
    if (/^[0-9a-f]{32}$/i.test(tokenId) && /^[0-9a-f]{32}$/i.test(secret)) {
      return { type: "v1", tokenId: tokenId.toLowerCase(), secret: secret.toLowerCase() };
    }
  }
  // Legacy format: .../{64-hex}
  const match = input.match(/[0-9a-f]{64}/i);
  if (match) return { type: "legacy", fullToken: match[0].toLowerCase() };
  throw new Error("Invalid VoidNote URL or token — expected 64-char hex or .../tokenId#secret");
}

// --- public API ---

/**
 * Create a VoidNote. Encrypts content client-side — server never sees plaintext.
 * Uses the v1 API: server generates tokenId, client holds the secret in the URL fragment.
 *
 * @param content   The secret text to encrypt and store
 * @param options   { apiKey, maxViews?, expiresIn? }
 * @param base      Override the base URL (default: https://voidnote.net)
 * @returns         { url, token, expiresAt } — url includes #secret, share the full url
 */
export async function create(
  content: string,
  options: CreateOptions,
  base = DEFAULT_BASE,
): Promise<CreateResult> {
  // Client generates only the secret — server generates the tokenId
  const secretBytes = new Uint8Array(16);
  crypto.getRandomValues(secretBytes);
  const secret = bufToHex(secretBytes);

  const { encrypted, iv } = await encryptContent(content, secret);
  const expiresIn = (options.expiresIn ?? 1) * 3600; // hours → seconds

  const res = await fetch(`${base}/api/v1/note/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({
      encrypted,
      iv,
      expiresIn,
      viewLimit: options.maxViews ?? 1,
    }),
  });

  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);

  // Server returns URL without the secret — append #secret for the shareable link
  return {
    url: `${json.url}#${secret}`,
    token: json.token,
    expiresAt: json.expiresAt,
  };
}

/**
 * Read and decrypt a VoidNote. Consumes one view — the note may self-destruct.
 *
 * Accepts both v1 URLs (https://voidnote.net/n/{tokenId}#{secret})
 * and legacy URLs (https://voidnote.net/note/{64-char-token}).
 *
 * @param urlOrToken  Full VoidNote URL or raw 64-char hex token (legacy)
 * @param base        Override the base URL (default: https://voidnote.net)
 */
export async function read(urlOrToken: string, base = DEFAULT_BASE): Promise<ReadResult> {
  const parsed = parseNoteUrl(urlOrToken);

  if (parsed.type === "v1") {
    const { tokenId, secret } = parsed;
    const res = await fetch(`${base}/api/v1/note/${tokenId}/consume/`);
    const json = (await res.json()) as any;
    if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
    const content = await decryptContent(json.encrypted, json.iv, secret);
    return {
      content,
      title: null,
      viewCount: 1,
      maxViews: (json.viewsRemaining ?? 0) + 1,
      destroyed: json.destroyed ?? false,
      viewsRemaining: json.viewsRemaining ?? 0,
    };
  }

  // Legacy: server decrypts and returns plaintext
  const res = await fetch(`${base}/api/note/${parsed.fullToken}/`);
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return {
    content: json.content,
    title: json.title ?? null,
    viewCount: json.viewCount,
    maxViews: json.maxViews,
    destroyed: json.destroyed,
  };
}

/**
 * Peek at note metadata without consuming a view.
 * Works with v1 URLs (and extracts the tokenId automatically).
 *
 * @param urlOrToken  VoidNote URL (v1 format with #secret, or just the 32-char tokenId)
 * @param base        Override the base URL
 */
export async function peek(urlOrToken: string, base = DEFAULT_BASE): Promise<PeekResult> {
  let tokenId: string;
  const hashIdx = urlOrToken.indexOf("#");
  const withoutHash = hashIdx !== -1 ? urlOrToken.slice(0, hashIdx) : urlOrToken;
  const lastSegment = withoutHash.replace(/\/$/, "").split("/").pop() ?? "";

  if (/^[0-9a-f]{32}$/i.test(lastSegment)) {
    tokenId = lastSegment.toLowerCase();
  } else if (/^[0-9a-f]{64}$/i.test(lastSegment)) {
    tokenId = lastSegment.slice(0, 32).toLowerCase();
  } else {
    const match = urlOrToken.match(/[0-9a-f]{32}/i);
    if (!match) throw new Error("Cannot extract tokenId from input");
    tokenId = match[0].toLowerCase();
  }

  const res = await fetch(`${base}/api/v1/note/${tokenId}/meta/`);
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json as PeekResult;
}

// ---------------------------------------------------------------------------
// Void Stream — live encrypted real-time channels
// ---------------------------------------------------------------------------

export interface StreamOptions {
  apiKey: string;
  title?: string;
  ttl?: 3600 | 21600 | 86400;
}

export interface StreamHandle {
  url: string;
  expiresAt: string;
  write(content: string): Promise<void>;
  close(): Promise<void>;
}

export interface WatchOptions {
  /** Password for a password-protected stream. */
  password?: string;
}

/** Error carrying the HTTP status and the server's error message. */
async function httpError(res: Response): Promise<Error> {
  let detail = "";
  try {
    const text = (await res.text()).trim();
    try {
      detail = (JSON.parse(text) as { error?: string }).error ?? text;
    } catch {
      detail = text;
    }
  } catch {
    // body unreadable — status alone
  }
  return new Error(`VoidNote: HTTP ${res.status}${detail ? ` — ${detail.slice(0, 300)}` : ""}`);
}

/**
 * Create a new Void Stream. Costs 1 credit.
 * The returned handle authenticates write() and close() with the same API key.
 */
export async function createStream(
  options: StreamOptions,
  base = DEFAULT_BASE,
): Promise<StreamHandle> {
  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const fullToken = bufToHex(tokenBytes);
  const tokenId = fullToken.slice(0, 32);
  const secret = fullToken.slice(32);
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${options.apiKey}`,
  };

  const res = await fetch(`${base}/api/stream/`, {
    method: "POST",
    headers,
    body: JSON.stringify({ tokenId, title: options.title, ttl: options.ttl ?? 3600 }),
  });
  if (!res.ok) throw await httpError(res);
  const json = (await res.json()) as any;
  if (!json.success) throw new Error(json.error ?? "VoidNote: stream creation failed");

  const url = `${json.siteUrl}/stream/${fullToken}`;

  return {
    url,
    expiresAt: json.expiresAt,
    async write(content: string) {
      const { encrypted, iv } = await encryptContent(content, secret);
      const r = await fetch(`${base}/api/stream/${fullToken}/write/`, {
        method: "POST",
        headers,
        body: JSON.stringify({ encryptedContent: encrypted, iv }),
      });
      if (!r.ok) throw await httpError(r);
    },
    async close() {
      const r = await fetch(`${base}/api/stream/${fullToken}/close/`, {
        method: "POST",
        headers,
        body: "{}",
      });
      if (!r.ok) throw await httpError(r);
    },
  };
}

/**
 * Obtain a stream access token (required to read events). Returns null when the
 * stream has already closed or expired.
 */
async function joinStream(base: string, token: string, password?: string): Promise<string | null> {
  const res = await fetch(`${base}/api/stream/${token}/join/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(password === undefined ? {} : { password }),
  });
  if (res.status === 410) return null;
  if (!res.ok) throw await httpError(res);
  const json = (await res.json()) as { accessToken?: string };
  if (!json.accessToken) throw new Error("VoidNote: join returned no access token");
  return json.accessToken;
}

/**
 * Watch a Void Stream. Yields decrypted messages as they arrive.
 * Joins the stream for an access token (re-joining when it expires) and
 * reconnects with Last-Event-ID until the stream closes or expires.
 * Throws on HTTP or network errors.
 */
export async function* watch(
  urlOrToken: string,
  base = DEFAULT_BASE,
  options: WatchOptions = {},
): AsyncGenerator<string> {
  const match = urlOrToken.match(/[0-9a-f]{64}/i);
  if (!match) throw new Error("No valid 64-char stream token found in input");
  const token = match[0].toLowerCase();
  const secret = token.slice(32, 64);

  const keyMat = await crypto.subtle.digest("SHA-256", hexToBytes(secret).buffer as ArrayBuffer);
  const key = await crypto.subtle.importKey(
    "raw",
    keyMat,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  let accessToken = await joinStream(base, token, options.password);
  if (accessToken === null) return;
  let rejoined = false;
  let lastId = "0";

  while (true) {
    const headers: Record<string, string> = {};
    if (lastId !== "0") headers["Last-Event-ID"] = lastId;

    const res = await fetch(
      `${base}/api/stream/${token}/events/?at=${encodeURIComponent(accessToken)}`,
      { headers },
    );

    // Access tokens live 30 minutes: re-join once, then give up on a repeat 401.
    if (res.status === 401 && !rejoined) {
      await res.body?.cancel().catch(() => {});
      accessToken = await joinStream(base, token, options.password);
      if (accessToken === null) return;
      rejoined = true;
      continue;
    }
    if (!res.ok || !res.body) throw await httpError(res);
    rejoined = false;

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let eventId = "";
    let eventData = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop()!;

        for (const line of lines) {
          if (line.startsWith("id: ")) {
            eventId = line.slice(4).trim();
          } else if (line.startsWith("data: ")) {
            eventData = line.slice(6);
          } else if (line === "" && eventData) {
            if (eventId) lastId = eventId;
            let data: any;
            try {
              data = JSON.parse(eventData);
            } catch {
              eventData = "";
              eventId = "";
              continue;
            }
            if (data.type === "closed" || data.type === "expired") return;
            if (data.enc && data.iv) {
              try {
                const plain = await crypto.subtle.decrypt(
                  { name: "AES-GCM", iv: hexToBytes(data.iv) },
                  key,
                  hexToBytes(data.enc),
                );
                yield new TextDecoder().decode(plain);
              } catch {
                // tampered or wrong key — skip
              }
            }
            eventData = "";
            eventId = "";
          }
        }
      }
    } finally {
      reader.cancel().catch(() => {});
    }
    // Segment ended — reconnect
  }
}

// --- Buy / Credits API ---

export interface CryptoOrderOptions {
  apiKey: string;
  bundleId: "test" | "starter" | "standard" | "pro";
  chain: "polygon" | "base" | "arbitrum" | "ethereum" | "bitcoin" | "tron";
  token: "USDT" | "USDC" | "ETH" | "BTC" | "TRX";
}

export interface CryptoOrder {
  orderId: string;
  toAddress: string;
  chain: string;
  token: string;
  amount: string;
  amountUsd: number;
  credits: number;
  expiresAt: string;
}

export interface SubmitPaymentOptions {
  apiKey: string;
  orderId: string;
  txHash: string;
}

export interface SubmitPaymentResult {
  credits: number;
  creditsAdded: number;
}

export async function createCryptoOrder(
  options: CryptoOrderOptions,
  base = DEFAULT_BASE,
): Promise<CryptoOrder> {
  const res = await fetch(`${base}/api/buy/crypto/create-order/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({ bundleId: options.bundleId, chain: options.chain, token: options.token }),
  });
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json as CryptoOrder;
}

export async function submitCryptoPayment(
  options: SubmitPaymentOptions,
  base = DEFAULT_BASE,
): Promise<SubmitPaymentResult> {
  const res = await fetch(`${base}/api/buy/crypto/submit-tx/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({ orderId: options.orderId, txHash: options.txHash }),
  });
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return { credits: json.credits, creditsAdded: json.creditsAdded };
}
