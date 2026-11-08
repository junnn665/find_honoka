// 使い方: node tools/encrypt.mjs "<合言葉>" <ほのかの顔フォルダ> <ほかの顔フォルダ>
// 顔画像（正方形JPEG）を暗号化して faces.enc.json に書き出す。元写真はリポジトリに入れないこと。
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { webcrypto as C } from 'node:crypto';
const [pass, dir, dir2] = process.argv.slice(2);
if (!pass || !dir || !dir2) { console.error('node tools/encrypt.mjs "<合言葉>" <ほのかフォルダ> <ほかの顔フォルダ>'); process.exit(1); }
const load = (d) => readdirSync(d).filter((f) => /\.jpe?g$/i.test(f)).sort().map((f) => 'data:image/jpeg;base64,' + readFileSync(`${d}/${f}`).toString('base64'));
const faces = load(dir), decoys = load(dir2);
const ITER = 600000;
const norm = pass.normalize('NFKC').toLowerCase().replace(/\s+/g, '').replace(/[\u3041-\u3096]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0x60));
const base = await C.subtle.importKey('raw', new TextEncoder().encode(norm), 'PBKDF2', false, ['deriveKey']);
const mk = (salt) => C.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
// 同じ合言葉なら前のファイルの salt を使い回す（「この端末で覚える」が切れないように）
let salt = null;
try {
  const old = JSON.parse(readFileSync('public/faces.enc.json', 'utf8'));
  const s0 = Buffer.from(old.salt, 'base64');
  await C.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(old.iv, 'base64') }, await mk(s0), Buffer.from(old.data, 'base64'));
  salt = new Uint8Array(s0); console.log('合言葉が同じなので、前の salt を使います');
} catch {}
if (!salt) salt = C.getRandomValues(new Uint8Array(16));
const iv = C.getRandomValues(new Uint8Array(12));
const key = await mk(salt);
const ct = new Uint8Array(await C.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify({ faces, decoys }))));
const b64 = (u) => Buffer.from(u).toString('base64');
const enc = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(ct) });
writeFileSync('public/faces.enc.json', enc);
console.log(`暗号化しました: ほのか ${faces.length}枚・ほか ${decoys.length}枚 / ${Math.round(enc.length / 1024)}KB`);
