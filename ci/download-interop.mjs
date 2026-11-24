// The browser's decryption (ui/src/seal.ts, decryptDownload) against a download the Rust agent produced
// (crates/protocol/src/download.rs, interop_sample): same key agreement, key derivation and frames.
//   FENRIR_INTEROP_DIR=dir cargo test -p protocol interop_sample && node ci/download-interop.mjs dir ui/src/seal.ts
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import ts from "./../ui/node_modules/typescript/lib/typescript.js";

const [dir, sealTs] = process.argv.slice(2);
const js = ts.transpileModule(readFileSync(sealTs, "utf8"), { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } }).outputText;
const out = join(mkdtempSync(join(tmpdir(), "seal-")), "seal.mjs");
writeFileSync(out, js);
const { decryptDownload, unb64 } = await import(out);

const priv = readFileSync(join(dir, "private.bin"));
// PKCS#8 wrapping of a raw X25519 private key (RFC 8410).
const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), priv]);
const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]);
const pub = unb64(readFileSync(join(dir, "public.b64"), "utf8").trim());
const header = JSON.parse(readFileSync(join(dir, "header.json"), "utf8"));
const stream = readFileSync(join(dir, "stream.bin"));
const plain = await decryptDownload(key, pub, header, stream.buffer.slice(stream.byteOffset, stream.byteOffset + stream.byteLength));
const want = readFileSync(join(dir, "plain.bin"));
if (Buffer.compare(Buffer.from(plain), want) !== 0) throw new Error("decrypted bytes differ");
// Cut short: refused.
let refused = false;
try {
  await decryptDownload(key, pub, header, stream.buffer.slice(stream.byteOffset, stream.byteOffset + 1000));
} catch { refused = true; }
if (!refused) throw new Error("a truncated download was accepted");
console.log(`download interop OK (${plain.length} bytes)`);
