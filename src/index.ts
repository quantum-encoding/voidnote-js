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

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
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
    }),
  });

  const json = (await res.json()) as any;
  if (!res.ok || !json.success) throw new Error(json.error ?? `HTTP ${res.status}`);

  return {
    url: `${json.siteUrl}/note/${fullToken}`,
    expiresAt: json.expiresAt,
  };
}
