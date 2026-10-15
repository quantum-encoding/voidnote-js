// Live round trip against voidnote.net (creates real anonymous notes).
// Run from typescript/ after `npm run build`:
//   node test/live.mjs [in.json] [out.json] [--read-only]
// in.json holds notes another SDK created; this script reads them (cross-language),
// then creates its own and writes them to out.json for the next SDK.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";
import { create, read, peek, VoidNoteError } from "../dist/index.js";

const LANG = "typescript";
const PASSWORD = "pässwörd-日本🔑";
const base = process.env.VOIDNOTE_BASE ?? "https://voidnote.net";
const [inFile, outFile] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const readOnly = process.argv.includes("--read-only");
const pass = (step) => console.log(`PASS ${LANG}: ${step}`);

async function expectError(promise, check) {
  try {
    await promise;
  } catch (e) {
    assert.ok(e instanceof VoidNoteError, `expected VoidNoteError, got ${e}`);
    check(e);
    return e;
  }
  assert.fail("expected an error");
}

if (inFile && existsSync(inFile)) {
  const prev = JSON.parse(readFileSync(inFile, "utf8"));
  const a = await read(prev.sha256, base);
  assert.equal(a.content, prev.content_sha256);
  assert.equal(a.kdf, "sha256");
  assert.equal(a.destroyed, true);
  pass(`read ${prev.from} sha256 note (cross-language), destroyed on last view`);
  const b = await read(prev.pbkdf2, { base, password: prev.password });
  assert.equal(b.content, prev.content_pbkdf2);
  assert.equal(b.kdf, "pbkdf2-sha256-600k");
  assert.equal(b.destroyed, true);
  pass(`read ${prev.from} pbkdf2 note with non-ASCII password (cross-language)`);
}

if (!readOnly) {
  const out = { from: LANG, password: PASSWORD };

  out.content_sha256 = `live sha256 from ${LANG} — ✓ 日本`;
  const s = await create(out.content_sha256, { maxViews: 2 }, base);
  assert.equal(s.kdf, "sha256");
  const sMeta = await peek(s.url, base);
  assert.deepEqual([sMeta.exists, sMeta.kdf, sMeta.viewsRemaining], [true, "sha256", 2]);
  const sRead = await read(s.url, base);
  assert.equal(sRead.content, out.content_sha256);
  assert.equal(sRead.viewsRemaining, 1);
  out.sha256 = s.url;
  pass("anonymous sha256 create → peek → read");

  out.content_pbkdf2 = `live pbkdf2 from ${LANG} — 🔒`;
  const p = await create(out.content_pbkdf2, { password: PASSWORD, maxViews: 2 }, base);
  assert.equal(p.kdf, "pbkdf2-sha256-600k");
  assert.equal((await peek(p.url, base)).kdf, "pbkdf2-sha256-600k");
  await expectError(read(p.url, base), (e) => assert.equal(e.code, "password_required"));
  assert.equal((await peek(p.url, base)).viewsRemaining, 2);
  pass("pbkdf2 read without password refused before consume (views still 2)");
  const pRead = await read(p.url, { base, password: PASSWORD });
  assert.equal(pRead.content, out.content_pbkdf2);
  assert.equal(pRead.viewsRemaining, 1);
  out.pbkdf2 = p.url;
  pass("anonymous pbkdf2 create → read with non-ASCII password");

  await expectError(create("x", { apiKey: "vn_invalid_live_check" }, base), (e) => {
    assert.equal(e.status, 401);
    assert.match(e.message, /Invalid API key\./);
  });
  pass("invalid API key surfaces 401 \"Invalid API key.\"");

  if (outFile) writeFileSync(outFile, JSON.stringify(out, null, 2));
}
