/**
 * VoidNote SDK — TypeScript/Node.js
 *
 * npm install voidnote-sdk
 *
 * Works in Node.js 18+, Deno, Bun, Cloudflare Workers, and modern browsers
 * (anything with Web Crypto API + fetch).
 */

/**
 * How a note's AES key is derived from the 32-hex secret in its link.
 *   sha256:             key = SHA-256(secret bytes)
 *   pbkdf2-sha256-600k: key = PBKDF2-HMAC-SHA256(password UTF-8, salt = secret bytes, 600000 iterations)
 */
export type NoteKdf = "sha256" | "pbkdf2-sha256-600k";

export const PBKDF2_ITERATIONS = 600_000;

export interface ReadResult {
  content: string;
  title: string | null;
  viewCount: number;
  maxViews: number;
  destroyed: boolean;
  viewsRemaining?: number; // v1 URLs only
  kdf?: NoteKdf;           // v1 URLs only
}

export interface ReadOptions {
  /** The sender's password, for notes created with one. Ignored for notes without one. */
  password?: string;
  /** Override the base URL (default: https://voidnote.net). */
  base?: string;
}

export interface CreateOptions {
  /** vn_... key from a free account. Without one the note is anonymous (up to 168 hours and 10 views). */
  apiKey?: string;
  /** Protect the note with a password as well as the link (kdf pbkdf2-sha256-600k). */
  password?: string;
  /** Views before the note is destroyed, default 1. Up to 10 anonymous, 100 with an API key. */
  maxViews?: number;
  /** Hours until expiry, default 1. Up to 168 anonymous, 720 with an API key. */
  expiresIn?: number;
}

export interface CreateResult {
  url: string;      // full shareable link — includes #secret fragment for v1 notes
  token: string;    // 32-char tokenId
  expiresAt: string;
  viewLimit: number;
  kdf: NoteKdf;
}

export interface PeekResult {
  exists: boolean;
  type?: string;
  createdAt?: string;
  expiresAt?: string;
  viewLimit?: number;
  viewsRemaining?: number;
  kdf?: NoteKdf;
}

export type VoidNoteErrorCode =
  | "http"               // the server refused the request; see status and retryAfter
  | "not_found"          // the note does not exist, expired, or its views are used up
  | "password_required"  // the note needs a password; no view was used
  | "unsupported_kdf"    // the note uses a key derivation this SDK version cannot do; no view was used
  | "decryption_failed"; // wrong password or link; the view was used

/** Every failure the notes and streams API reports. */
export class VoidNoteError extends Error {
  readonly code: VoidNoteErrorCode;
  /** HTTP status, for code "http". */
  readonly status: number | null;
  /** Seconds the server asked to wait (Retry-After), when it sent one. */
  readonly retryAfter: number | null;

  constructor(message: string, code: VoidNoteErrorCode, status: number | null = null, retryAfter: number | null = null) {
    super(message);
    this.name = "VoidNoteError";
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

const DEFAULT_BASE = "https://voidnote.net";
const KDFS: readonly NoteKdf[] = ["sha256", "pbkdf2-sha256-600k"];

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

/** Retry-After as seconds: either delta-seconds or an HTTP date. */
function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const at = Date.parse(trimmed);
  return Number.isNaN(at) ? null : Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

/** VoidNoteError carrying the HTTP status, Retry-After and the server's error message. */
async function httpError(res: Response): Promise<VoidNoteError> {
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
  const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
  const message =
    `VoidNote: HTTP ${res.status}${detail ? ` — ${detail.slice(0, 300)}` : ""}` +
    (retryAfter !== null ? ` (retry after ${retryAfter}s)` : "");
  return new VoidNoteError(message, "http", res.status, retryAfter);
}

async function getJson(url: string, init?: RequestInit): Promise<any> {
  const res = await fetch(url, init);
  if (!res.ok) throw await httpError(res);
  return res.json();
}

async function deriveKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return deriveNoteKey(secret, "sha256", null, usage);
}

async function deriveNoteKey(
  secret: string,
  kdf: NoteKdf,
  password: string | null,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  const secretBytes = hexToBytes(secret);
  let keyMat: ArrayBuffer;
  if (kdf === "pbkdf2-sha256-600k") {
    if (!password) {
      throw new VoidNoteError("VoidNote: this note needs a password", "password_required");
    }
    const base = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    keyMat = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: secretBytes, iterations: PBKDF2_ITERATIONS },
      base,
      256,
    );
  } else {
    keyMat = await crypto.subtle.digest("SHA-256", secretBytes);
  }
  return crypto.subtle.importKey("raw", keyMat, { name: "AES-GCM", length: 256 }, false, usage);
}

async function encryptWithKey(content: string, key: CryptoKey): Promise<{ encrypted: string; iv: string }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(content),
  );
  return { encrypted: bufToHex(new Uint8Array(ciphertext)), iv: bufToHex(iv) };
}

async function encryptContent(
  content: string,
  secret: string,
): Promise<{ encrypted: string; iv: string }> {
  return encryptWithKey(content, await deriveKey(secret, ["encrypt"]));
}

async function decryptNote(
  encHex: string,
  ivHex: string,
  secret: string,
  kdf: NoteKdf,
  password: string | null,
): Promise<string> {
  const key = await deriveNoteKey(secret, kdf, password, ["decrypt"]);
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(ivHex) }, key, hexToBytes(encHex));
  } catch {
    throw new VoidNoteError(
      kdf === "sha256"
        ? "VoidNote: decryption failed — the link's key is wrong or incomplete"
        : "VoidNote: decryption failed — wrong password (this read used a view)",
      "decryption_failed",
    );
  }
  return new TextDecoder().decode(plain);
}

function checkKdf(kdf: unknown): NoteKdf {
  const name = kdf ?? "sha256";
  if (!KDFS.includes(name as NoteKdf)) {
    throw new VoidNoteError(
      `VoidNote: this note uses key derivation "${String(name)}", which this SDK version cannot decrypt — upgrade voidnote-sdk`,
      "unsupported_kdf",
    );
  }
  return name as NoteKdf;
}

function positiveInt(name: string, value: number): number {
  if (!Number.isInteger(value) || value < 1) throw new RangeError(`${name} must be a positive integer`);
  return value;
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
 * No API key is needed: without one the note is anonymous, held to 168 hours and
 * 10 views, and rate-limited per IP. With a password the key is derived with
 * PBKDF2 and the reader needs both the link and the password.
 *
 * @param content   The secret text to encrypt and store
 * @param options   { apiKey?, password?, maxViews?, expiresIn? }
 * @param base      Override the base URL (default: https://voidnote.net)
 * @returns         { url, token, expiresAt, viewLimit, kdf } — url includes #secret, share the full url
 * @throws          VoidNoteError with the server's message (e.g. HTTP 429 with retryAfter)
 */
export async function create(
  content: string,
  options: CreateOptions = {},
  base = DEFAULT_BASE,
): Promise<CreateResult> {
  if (options.password === "") throw new TypeError("password must not be empty");
  const kdf: NoteKdf = options.password ? "pbkdf2-sha256-600k" : "sha256";
  const viewLimit = positiveInt("maxViews", options.maxViews ?? 1);
  const expiresIn = positiveInt("expiresIn", options.expiresIn ?? 1) * 3600; // hours → seconds

  // Client generates only the secret — server generates the tokenId
  const secretBytes = new Uint8Array(16);
  crypto.getRandomValues(secretBytes);
  const secret = bufToHex(secretBytes);

  const key = await deriveNoteKey(secret, kdf, options.password ?? null, ["encrypt"]);
  const { encrypted, iv } = await encryptWithKey(content, key);

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.apiKey) headers.Authorization = `Bearer ${options.apiKey}`;

  const json = await getJson(`${base}/api/v1/note/`, {
    method: "POST",
    headers,
    body: JSON.stringify({ encrypted, iv, expiresIn, viewLimit, kdf }),
  });

  // Server returns URL without the secret — append #secret for the shareable link
  return {
    url: `${json.url}#${secret}`,
    token: json.token,
    expiresAt: json.expiresAt,
    viewLimit: json.viewLimit ?? viewLimit,
    kdf: json.kdf ?? kdf,
  };
}

/**
 * Read and decrypt a VoidNote. Consumes one view — the note may self-destruct.
 *
 * Accepts both v1 URLs (https://voidnote.net/n/{tokenId}#{secret})
 * and legacy URLs (https://voidnote.net/note/{64-char-token}).
 *
 * v1 notes are checked first without using a view: a missing note, a note that
 * needs a password when none was given, or an unknown key derivation throws a
 * VoidNoteError ("not_found", "password_required", "unsupported_kdf") and the
 * view stays unused. A wrong password is only detectable after the view is used.
 *
 * @param urlOrToken     Full VoidNote URL or raw 64-char hex token (legacy)
 * @param baseOrOptions  Base URL override, or { password?, base? }
 */
export async function read(urlOrToken: string, baseOrOptions: string | ReadOptions = {}): Promise<ReadResult> {
  const options: ReadOptions = typeof baseOrOptions === "string" ? { base: baseOrOptions } : baseOrOptions;
  const base = options.base ?? DEFAULT_BASE;
  const parsed = parseNoteUrl(urlOrToken);

  if (parsed.type === "v1") {
    const { tokenId, secret } = parsed;
    const meta = (await getJson(`${base}/api/v1/note/${tokenId}/meta/`)) as PeekResult;
    if (!meta.exists) {
      throw new VoidNoteError("VoidNote: note not found, expired or already destroyed", "not_found");
    }
    const metaKdf = checkKdf(meta.kdf);
    if (metaKdf !== "sha256" && !options.password) {
      throw new VoidNoteError(
        "VoidNote: this note needs a password — pass { password } (no view was used)",
        "password_required",
      );
    }

    const json = await getJson(`${base}/api/v1/note/${tokenId}/consume/`);
    const kdf = checkKdf(json.kdf ?? metaKdf);
    const content = await decryptNote(json.encrypted, json.iv, secret, kdf, options.password ?? null);
    const viewsRemaining: number = json.viewsRemaining ?? 0;
    const maxViews = meta.viewLimit ?? viewsRemaining + 1;
    return {
      content,
      title: null,
      viewCount: maxViews - viewsRemaining,
      maxViews,
      destroyed: json.destroyed ?? false,
      viewsRemaining,
      kdf,
    };
  }

  // Legacy: server decrypts and returns plaintext
  const json = await getJson(`${base}/api/note/${parsed.fullToken}/`);
  return {
    content: json.content,
    title: json.title ?? null,
    viewCount: json.viewCount,
    maxViews: json.maxViews,
    destroyed: json.destroyed,
  };
}

/**
 * Peek at note metadata without consuming a view. `kdf` tells whether the note
 * needs a password ("pbkdf2-sha256-600k") or not ("sha256").
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

  return (await getJson(`${base}/api/v1/note/${tokenId}/meta/`)) as PeekResult;
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

/**
 * Create a new Void Stream. Requires an API key from a free account.
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
