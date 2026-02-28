/**
 * VoidNote SDK — TypeScript/Node.js
 *
 * npm install voidnote
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
}

export interface CreateOptions {
  title?: string;
  maxViews?: number;  // 1–100, default 1
  apiKey: string;     // vn_... from your dashboard
  expiresIn?: 1 | 6 | 24 | 72 | 168 | 720;  // hours, default 24
  noteType?: "secure" | "pipe";               // default "secure"
}

export interface CreateResult {
  url: string;        // full shareable link
  expiresAt: string;
}

const DEFAULT_BASE = "https://voidnote.net";

// --- helpers ---

function extractToken(input: string): string {
  const match = input.match(/[0-9a-f]{64}/i);
  if (!match) throw new Error("No valid 64-char token found in input");
  return match[0].toLowerCase();
}

function bufToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const ab = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(ab);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function generateToken(): Promise<{ fullToken: string; tokenId: string; secret: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const fullToken = bufToHex(bytes);
  return { fullToken, tokenId: fullToken.slice(0, 32), secret: fullToken.slice(32) };
}

async function encryptContent(
  content: string,
  secret: string,
): Promise<{ encryptedContent: string; iv: string }> {
  const keyMat = await crypto.subtle.digest("SHA-256", hexToBytes(secret).buffer as ArrayBuffer);
  const key = await crypto.subtle.importKey(
    "raw", keyMat, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(content),
  );
  return { encryptedContent: bufToHex(new Uint8Array(ciphertext)), iv: bufToHex(iv) };
}

// --- public API ---

/**
 * Read a VoidNote. Consumes one view — the note may be destroyed after this call.
 *
 * @param urlOrToken  Full VoidNote URL or raw 64-char hex token
 * @param base        Override the base URL (default: https://voidnote.net)
 */
export async function read(urlOrToken: string, base = DEFAULT_BASE): Promise<ReadResult> {
  const token = extractToken(urlOrToken);
  const res = await fetch(`${base}/api/note/${token}`);
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
 * Create a VoidNote. Requires an API key from your dashboard.
 * Encrypts the content client-side — the server never sees the plaintext.
 *
 * @param content   The secret text to encrypt and store
 * @param options   { apiKey, title?, maxViews? }
 * @param base      Override the base URL (default: https://voidnote.net)
 */
export async function create(
  content: string,
  options: CreateOptions,
  base = DEFAULT_BASE,
): Promise<CreateResult> {
  const { fullToken, tokenId, secret } = await generateToken();
  const { encryptedContent, iv } = await encryptContent(content, secret);

  const res = await fetch(`${base}/api/notes`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({
      tokenId,
      encryptedContent,
      iv,
      maxViews: options.maxViews ?? 1,
      title: options.title,
      expiresIn: options.expiresIn ?? 24,
      noteType: options.noteType ?? "secure",
    }),
  });

  const json = (await res.json()) as any;
  if (!res.ok || !json.success) throw new Error(json.error ?? `HTTP ${res.status}`);

  return {
    url: `${json.siteUrl}/note/${fullToken}`,
    expiresAt: json.expiresAt,
  };
}

// ---------------------------------------------------------------------------
// Void Stream — live encrypted real-time channels
// ---------------------------------------------------------------------------

export interface StreamOptions {
  apiKey: string;
  title?: string;
  ttl?: 3600 | 21600 | 86400; // seconds — defaults to 3600 (1h)
}

export interface StreamHandle {
  /** The shareable stream URL (contains the decryption key in the path) */
  url: string;
  expiresAt: string;
  /** Encrypt and push a message to the stream */
  write(content: string): Promise<void>;
  /** Close the stream — viewers see a "closed" event, all content self-destructs */
  close(): Promise<void>;
}

/**
 * Create a new Void Stream. Requires an API key. Costs 1 credit.
 * Returns a StreamHandle with .url, .write(), and .close().
 *
 * @example
 * const stream = await createStream({ apiKey: "vn_..." });
 * console.log(stream.url);  // share this with viewers
 * await stream.write("Deployment starting…");
 * await stream.write("Done — 47/47 tests passed");
 * await stream.close();
 */
export async function createStream(
  options: StreamOptions,
  base = DEFAULT_BASE,
): Promise<StreamHandle> {
  const { fullToken, tokenId, secret } = await generateToken();

  const res = await fetch(`${base}/api/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({
      tokenId,
      title: options.title,
      ttl: options.ttl ?? 3600,
    }),
  });

  const json = (await res.json()) as any;
  if (!res.ok || !json.success) throw new Error(json.error ?? `HTTP ${res.status}`);

  const url = `${json.siteUrl}/stream/${fullToken}`;

  return {
    url,
    expiresAt: json.expiresAt,
    async write(content: string) {
      await writeToStream(fullToken, secret, content, base);
    },
    async close() {
      await closeStream(fullToken, base);
    },
  };
}

async function writeToStream(
  fullToken: string,
  secret: string,
  content: string,
  base: string,
): Promise<void> {
  const { encryptedContent, iv } = await encryptContent(content, secret);
  const res = await fetch(`${base}/api/stream/${fullToken}/write`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ encryptedContent, iv }),
  });
  const json = (await res.json()) as any;
  if (!res.ok || !json.success) throw new Error(json.error ?? `HTTP ${res.status}`);
}

async function closeStream(fullToken: string, base: string): Promise<void> {
  const res = await fetch(`${base}/api/stream/${fullToken}/close`, { method: "POST" });
  if (!res.ok) {
    const json = (await res.json()) as any;
    throw new Error(json.error ?? `HTTP ${res.status}`);
  }
}

/**
 * Watch a Void Stream. Yields decrypted messages as they arrive.
 * Automatically reconnects using SSE Last-Event-ID until the stream closes.
 *
 * Works in Node.js 18+, Deno, Bun, and Cloudflare Workers.
 *
 * @example
 * for await (const message of watch("https://voidnote.net/stream/abc123...")) {
 *   console.log(message);
 * }
 */
export async function* watch(
  urlOrToken: string,
  base = DEFAULT_BASE,
): AsyncGenerator<string> {
  const token = extractToken(urlOrToken);
  const secret = token.slice(32, 64);

  // Derive AES key once
  const keyMat = await crypto.subtle.digest("SHA-256", hexToBytes(secret).buffer as ArrayBuffer);
  const key = await crypto.subtle.importKey("raw", keyMat, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

  let lastId = "0";

  while (true) {
    const headers: Record<string, string> = {};
    if (lastId !== "0") headers["Last-Event-ID"] = lastId;

    let res: Response;
    try {
      res = await fetch(`${base}/api/stream/${token}/events`, { headers });
    } catch {
      break; // network error — stop
    }

    if (!res.ok || !res.body) break;

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
            try { data = JSON.parse(eventData); } catch { eventData = ""; eventId = ""; continue; }

            if (data.type === "closed" || data.type === "expired") return;

            if (data.enc && data.iv) {
              const ciphertext = hexToBytes(data.enc);
              const iv = hexToBytes(data.iv);
              try {
                const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
                yield new TextDecoder().decode(plain);
              } catch {
                // tampered or wrong key — skip silently
              }
            }

            eventData = "";
            eventId = "";
          }
        }
      }
    } finally {
      reader.cancel().catch(() => { /* ignore */ });
    }
    // Stream segment ended — loop to reconnect with Last-Event-ID
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
  amount: string;      // human-readable (e.g. "5.000000")
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

/**
 * Create a crypto payment order for credits.
 * Returns an address + exact amount to send, valid for 1 hour.
 *
 * @example
 * const order = await createCryptoOrder({ apiKey: "vn_...", bundleId: "starter", chain: "polygon", token: "USDT" });
 * console.log(`Send ${order.amount} ${order.token} to ${order.toAddress}`);
 */
export async function createCryptoOrder(
  options: CryptoOrderOptions,
  base = DEFAULT_BASE,
): Promise<CryptoOrder> {
  const res = await fetch(`${base}/api/buy/crypto/create-order`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({
      bundleId: options.bundleId,
      chain: options.chain,
      token: options.token,
    }),
  });
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json as CryptoOrder;
}

/**
 * Submit a transaction hash to confirm a crypto payment.
 * Verifies on-chain and credits your account instantly.
 *
 * @example
 * const result = await submitCryptoPayment({ apiKey: "vn_...", orderId: order.orderId, txHash: "0x..." });
 * console.log(`New balance: ${result.credits} credits`);
 */
export async function submitCryptoPayment(
  options: SubmitPaymentOptions,
  base = DEFAULT_BASE,
): Promise<SubmitPaymentResult> {
  const res = await fetch(`${base}/api/buy/crypto/submit-tx`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify({
      orderId: options.orderId,
      txHash: options.txHash,
    }),
  });
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
  return { credits: json.credits, creditsAdded: json.creditsAdded };
}
