import fs from "node:fs";
import crypto from "node:crypto";

const SOURCE = "src/main.js";
const MANIFEST = "manifest.json";
const OUT_DIR = "dist";
const HARD_LIMIT = 2 * 1024 * 1024;

const code = fs.readFileSync(SOURCE, "utf8");
const manifestText = fs.readFileSync(MANIFEST, "utf8");
const manifest = JSON.parse(manifestText);

const banned = [
  [/eval\s*\(/, "eval("],
  [/new\s+Function\s*\(/, "new Function("],
  [/__TAURI__/, "__TAURI__"],
  [/\blocalStorage\b/, "localStorage"],
  [/import\s*\(/, "dynamic import("],
  [/^\s*import\s/m, "bare import"],
];
for (const [re, name] of banned) {
  if (re.test(code)) throw new Error("bundle contains banned pattern: " + name);
}

const bytes = Buffer.byteLength(code);
if (bytes > HARD_LIMIT) throw new Error(`bundle too large: ${bytes} > ${HARD_LIMIT}`);

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const codeBuf = Buffer.from(code, "utf8");
const manifestBuf = Buffer.from(manifestText, "utf8");

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(`${OUT_DIR}/main.js`, codeBuf);
fs.writeFileSync(`${OUT_DIR}/manifest.json`, manifestBuf);

const checksums = [
  `${sha256(codeBuf)}  main.js`,
  `${sha256(manifestBuf)}  manifest.json`,
  "",
].join("\n");
fs.writeFileSync(`${OUT_DIR}/checksums.txt`, checksums);

console.log(`built ${OUT_DIR}/main.js (${bytes} bytes), ${manifest.id} v${manifest.version}`);
