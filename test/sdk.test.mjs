// Unit tests against a mocked fetch. Run: npm test
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { create, read, peek, VoidNoteError } from "../dist/index.js";

// Cross-client known answers shared with the iOS and Android suites
// (secret, iv and ciphertexts produced with WebCrypto).
const KAT_SECRET = "00112233445566778899aabbccddeeff";
const KAT_IV = "a1b2c3d4e5f6000102030405";
const KAT = {
  sha256: { encrypted: "8f6ee0eb13334ea99cf53aa86bf4dc0fa4686b9c74f1bf98f3aa4bc216d70fc058ba9452266c57c681a5", plain: "voidnote-v1-sha256-kat ✓" },
  pbkdf2: { encrypted: "3ca068b802bd8f8d25145619048f5de9b50ae3319ad9bc9f6af38bd9980107a311fb228dfd0b3e6b2c24", password: "correct horse battery staple", plain: "voidnote-v1-pbkdf2-kat ✓" },
  unicode: { encrypted: "c9aa7b0cd91b24f9c7982e6c0acb6233391307fc327b512c1ec87571aa62dbc5", password: "pässwörd-日本", plain: "unicode password" },
};
const TOKEN = "0123456789abcdef0123456789abcdef";
const BASE = "https://vn.test";
const URL_ = `${BASE}/n/${TOKEN}#${KAT_SECRET}`;

const realFetch = globalThis.fetch;
let calls = [];

function mockFetch(routes) {
  calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    for (const [suffix, handler] of Object.entries(routes)) {
      if (String(url).endsWith(suffix)) return handler(init);
    }
    throw new Error(`unexpected fetch ${url}`);
  };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

const meta = (kdf, extra = {}) => () =>
  json({ token: TOKEN, exists: true, type: "note", viewLimit: 2, viewsRemaining: 2, kdf, ...extra });
const consume = (kdf, encrypted) => () =>
  json({ token: TOKEN, encrypted, iv: KAT_IV, kdf, consumed: true, viewsRemaining: 1, destroyed: false });

afterEach(() => {
  globalThis.fetch = realFetch;
});

// --- create ---

function createRoute(capture) {
  return {
    "/api/v1/note/": (init) => {
      capture.body = JSON.parse(init.body);
      capture.headers = init.headers;
      return json({ token: TOKEN, url: `${BASE}/n/${TOKEN}`, expiresAt: "2026-10-15 12:00:00", viewLimit: capture.body.viewLimit, kdf: capture.body.kdf }, 201);
    },
  };
}

async function openCreated(capture, url, kdf, password) {
  const secret = url.split("#")[1];
  const h = (x) => Buffer.from(x, "hex");
  let keyMat;
  if (kdf === "sha256") {
    keyMat = await crypto.subtle.digest("SHA-256", h(secret));
  } else {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    keyMat = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: h(secret), iterations: 600000 }, base, 256);
  }
  const key = await crypto.subtle.importKey("raw", keyMat, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: h(capture.body.iv) }, key, h(capture.body.encrypted));
  return new TextDecoder().decode(plain);
}

test("create without an API key sends no Authorization header and anonymous-safe defaults", async () => {
  const cap = {};
  mockFetch(createRoute(cap));
  const res = await create("hello", {}, BASE);
  assert.equal("Authorization" in cap.headers, false);
  assert.deepEqual(
    { expiresIn: cap.body.expiresIn, viewLimit: cap.body.viewLimit, kdf: cap.body.kdf },
    { expiresIn: 3600, viewLimit: 1, kdf: "sha256" },
  );
  assert.match(res.url, new RegExp(`^${BASE}/n/${TOKEN}#[0-9a-f]{32}$`));
  assert.equal(res.kdf, "sha256");
  assert.equal(await openCreated(cap, res.url, "sha256"), "hello");
});

test("create with no options argument at all is anonymous", async () => {
  const cap = {};
  mockFetch(createRoute(cap));
  await create("x");
  assert.equal(calls[0].url, "https://voidnote.net/api/v1/note/");
  assert.equal("Authorization" in cap.headers, false);
});

test("create with an API key sends Bearer auth", async () => {
  const cap = {};
  mockFetch(createRoute(cap));
  await create("hello", { apiKey: "vn_test" }, BASE);
  assert.equal(cap.headers.Authorization, "Bearer vn_test");
});

test("create with a password sends kdf pbkdf2-sha256-600k and derives the key from it", async () => {
  const cap = {};
  mockFetch(createRoute(cap));
  const res = await create("guarded", { password: "pässwörd-日本", maxViews: 3, expiresIn: 2 }, BASE);
  assert.equal(cap.body.kdf, "pbkdf2-sha256-600k");
  assert.equal(cap.body.viewLimit, 3);
  assert.equal(cap.body.expiresIn, 7200);
  assert.equal(res.kdf, "pbkdf2-sha256-600k");
  assert.equal(await openCreated(cap, res.url, "pbkdf2-sha256-600k", "pässwörd-日本"), "guarded");
});

test("create refuses an empty password instead of making an unprotected note", async () => {
  mockFetch({});
  await assert.rejects(create("x", { password: "" }, BASE), TypeError);
  assert.equal(calls.length, 0);
});

test("create surfaces 429 with Retry-After", async () => {
  mockFetch({ "/api/v1/note/": () => json({ error: "Too many notes created. Try again shortly." }, 429, { "Retry-After": "60" }) });
  await assert.rejects(create("x", {}, BASE), (e) => {
    assert.ok(e instanceof VoidNoteError);
    assert.equal(e.code, "http");
    assert.equal(e.status, 429);
    assert.equal(e.retryAfter, 60);
    assert.match(e.message, /Too many notes created/);
    return true;
  });
});

test("create surfaces the server's 400 limit message", async () => {
  mockFetch({ "/api/v1/note/": () => json({ error: "viewLimit must be 1–10 without an account." }, 400) });
  await assert.rejects(create("x", { maxViews: 50 }, BASE), /viewLimit must be 1–10 without an account\./);
});

// --- read ---

test("read decrypts the sha256 KAT", async () => {
  mockFetch({ "/meta/": meta("sha256"), "/consume/": consume("sha256", KAT.sha256.encrypted) });
  const note = await read(URL_, BASE);
  assert.equal(note.content, KAT.sha256.plain);
  assert.equal(note.kdf, "sha256");
  assert.equal(note.maxViews, 2);
  assert.equal(note.viewCount, 1);
  assert.equal(note.viewsRemaining, 1);
});

test("read decrypts the pbkdf2 KAT with the password", async () => {
  mockFetch({ "/meta/": meta("pbkdf2-sha256-600k"), "/consume/": consume("pbkdf2-sha256-600k", KAT.pbkdf2.encrypted) });
  const note = await read(URL_, { base: BASE, password: KAT.pbkdf2.password });
  assert.equal(note.content, KAT.pbkdf2.plain);
  assert.equal(note.kdf, "pbkdf2-sha256-600k");
});

test("read hashes a non-ASCII password as UTF-8 (KAT)", async () => {
  mockFetch({ "/meta/": meta("pbkdf2-sha256-600k"), "/consume/": consume("pbkdf2-sha256-600k", KAT.unicode.encrypted) });
  const note = await read(URL_, { base: BASE, password: KAT.unicode.password });
  assert.equal(note.content, KAT.unicode.plain);
});

test("read of a password note without a password fails before consume", async () => {
  mockFetch({ "/meta/": meta("pbkdf2-sha256-600k"), "/consume/": consume("pbkdf2-sha256-600k", KAT.pbkdf2.encrypted) });
  await assert.rejects(read(URL_, BASE), (e) => e instanceof VoidNoteError && e.code === "password_required");
  assert.equal(calls.some((c) => c.url.includes("/consume/")), false);
});

test("read with a wrong password reports decryption_failed", async () => {
  mockFetch({ "/meta/": meta("pbkdf2-sha256-600k"), "/consume/": consume("pbkdf2-sha256-600k", KAT.pbkdf2.encrypted) });
  await assert.rejects(read(URL_, { base: BASE, password: "wrong" }), (e) => e.code === "decryption_failed");
});

test("read of an unknown kdf fails before consume", async () => {
  mockFetch({ "/meta/": meta("argon2id"), "/consume/": consume("argon2id", KAT.sha256.encrypted) });
  await assert.rejects(read(URL_, { base: BASE, password: "x" }), (e) => e.code === "unsupported_kdf");
  assert.equal(calls.some((c) => c.url.includes("/consume/")), false);
});

test("read of a missing note reports not_found without consume", async () => {
  mockFetch({ "/meta/": () => json({ token: TOKEN, exists: false }) });
  await assert.rejects(read(URL_, BASE), (e) => e.code === "not_found");
  assert.equal(calls.length, 1);
});

test("read surfaces a 410 from consume", async () => {
  mockFetch({ "/meta/": meta("sha256"), "/consume/": () => json({ error: "Note not found or already destroyed." }, 410) });
  await assert.rejects(read(URL_, BASE), (e) => e.status === 410 && /already destroyed/.test(e.message));
});

// --- peek ---

test("peek exposes kdf", async () => {
  mockFetch({ "/meta/": meta("pbkdf2-sha256-600k") });
  const m = await peek(URL_, BASE);
  assert.equal(m.kdf, "pbkdf2-sha256-600k");
  assert.equal(m.viewsRemaining, 2);
});
