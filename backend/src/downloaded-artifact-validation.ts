// Pure validation of the files a browser actually downloaded during E2E.
// No file system access: scripts/verification/validate-downloaded-artifacts.ts
// reads the Playwright download sink and passes the files in.
//
// Fail closed: a file named like a Parser Studio artifact is validated against
// the Stellar structure contract unless the test that produced it explicitly
// declared its response synthetic with a reason. Content is never used to decide
// whether to skip a file, because a regression that removes the markers would
// otherwise look like "not an artifact".
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { checkConfStructure, checkFragmentStructure, checkPairConformance, type ConformanceFinding } from "./reference-conformance.js";

export interface DownloadedFile {
  readonly id: string;
  /** Downloads of one test share a key; only same-key files are paired. */
  readonly testKey: string;
  readonly name: string;
  readonly content: string;
  /** Reason when the test declared its backend response synthetic, else null. */
  readonly synthetic: string | null;
}

export interface DownloadFailure { readonly id: string; readonly name: string; readonly rules: readonly string[]; readonly messages: readonly string[] }

export interface DownloadReport {
  readonly total: number;
  readonly real: { fragments: number; confs: number; other: number; pairs: number; ambiguousPairs: number };
  readonly uniqueRealFragments: number;
  readonly synthetic: { count: number; reasons: string[] };
  readonly otherNames: string[];
  readonly failures: DownloadFailure[];
}

const FRAGMENT_NAME = /^customized_[A-Za-z0-9_]+$/;
const CONF_NAME = /^customized_[A-Za-z0-9_]+\.conf$/;

export function validateDownloads(files: readonly DownloadedFile[]): DownloadReport {
  const failures: DownloadFailure[] = [];
  const fail = (file: DownloadedFile, findings: readonly ConformanceFinding[]) => {
    if (findings.length) failures.push({ id: file.id, name: file.name, rules: findings.map(f => f.rule), messages: findings.map(f => f.message) });
  };
  const real = files.filter(f => f.synthetic === null);
  const synthetic = files.filter(f => f.synthetic !== null);
  const fragments = real.filter(f => FRAGMENT_NAME.test(f.name));
  const confs = real.filter(f => CONF_NAME.test(f.name));
  const other = real.filter(f => !FRAGMENT_NAME.test(f.name) && !CONF_NAME.test(f.name));

  const paired = new Set<string>();
  const ambiguousGroups = new Set<string>();
  let pairs = 0;
  for (const fragment of fragments) {
    const partners = confs.filter(c => c.testKey === fragment.testKey && c.name === fragment.name + ".conf");
    if (!partners.length) continue;
    const group = fragment.testKey + "/" + fragment.name;
    if (partners.length > 1 || fragments.filter(f => f.testKey === fragment.testKey && f.name === fragment.name).length > 1) {
      ambiguousGroups.add(group);
      continue;
    }
    const conf = partners[0]!;
    paired.add(fragment.id);
    paired.add(conf.id);
    pairs += 1;
    // The pair check runs both single-file checks plus the cross-file rules;
    // FRAG-* findings belong to the fragment, CONF-* and PAIR-* to the .conf.
    const findings = checkPairConformance({ parserName: fragment.name, ruby: fragment.content, conf: conf.content });
    fail(fragment, findings.filter(f => f.rule.startsWith("FRAG-")));
    fail(conf, findings.filter(f => !f.rule.startsWith("FRAG-")));
  }
  const ambiguousPairs = ambiguousGroups.size;

  for (const fragment of fragments) if (!paired.has(fragment.id)) fail(fragment, checkFragmentStructure(fragment.content));
  for (const conf of confs) if (!paired.has(conf.id)) fail(conf, checkConfStructure(conf.content, { parserName: conf.name.replace(/\.conf$/, "") }));

  return {
    total: files.length,
    real: { fragments: fragments.length, confs: confs.length, other: other.length, pairs, ambiguousPairs },
    uniqueRealFragments: new Set(fragments.map(f => f.content)).size,
    synthetic: { count: synthetic.length, reasons: [...new Set(synthetic.map(f => f.synthetic!))].sort() },
    otherNames: [...new Set(other.map(f => f.name))].sort(),
    failures,
  };
}

// ---- ZIP downloads ---------------------------------------------------------
// The package a user receives holds the pair plus manifest.json. This reader is
// deliberately small and strict (ZIP32, STORE or DEFLATE, flat ASCII names); it
// collects every integrity problem instead of stopping at the first.

const CRC_TABLE = Array.from({ length: 256 }, (_, i) => {
  let value = i;
  for (let step = 0; step < 8; step++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function crc32(bytes: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 255]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

export interface ExpandedZip { readonly entries: Array<{ name: string; content: string }>; readonly problems: string[] }

export function expandZipDownload(zip: Buffer): ExpandedZip {
  const entries: ExpandedZip["entries"] = [];
  const problems: string[] = [];
  let end = -1;
  for (let at = zip.length - 22; at >= Math.max(0, zip.length - 22 - 0xffff); at--) {
    if (zip.readUInt32LE(at) === 0x06054b50) { end = at; break; }
  }
  if (end < 0) return { entries, problems: ["ZIP_INVALID"] };
  const count = zip.readUInt16LE(end + 10);
  let cursor = zip.readUInt32LE(end + 16);
  for (let i = 0; i < count; i++) {
    if (cursor + 46 > zip.length || zip.readUInt32LE(cursor) !== 0x02014b50) { problems.push("ZIP_INVALID"); break; }
    const method = zip.readUInt16LE(cursor + 10);
    const crc = zip.readUInt32LE(cursor + 16);
    const compressed = zip.readUInt32LE(cursor + 20);
    const size = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const local = zip.readUInt32LE(cursor + 42);
    const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    cursor += 46 + nameLength + extraLength + commentLength;
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(name)) { problems.push("ZIP_UNSAFE_ENTRY_NAME " + JSON.stringify(name).slice(0, 60)); continue; }
    if (local + 30 > zip.length || zip.readUInt32LE(local) !== 0x04034b50) { problems.push("ZIP_INVALID " + name); continue; }
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const stored = zip.subarray(start, start + compressed);
    let bytes: Buffer;
    try {
      if (method === 0) bytes = stored;
      else if (method === 8) bytes = inflateRawSync(stored);
      else { problems.push("ZIP_UNSUPPORTED_METHOD " + name); continue; }
    } catch { problems.push("ZIP_INVALID " + name); continue; }
    if (bytes.length !== size) problems.push("ZIP_SIZE_MISMATCH " + name);
    if (crc32(bytes) !== crc) problems.push("ZIP_CRC_MISMATCH " + name);
    entries.push({ name, content: bytes.toString("utf8") });
  }
  const sha = (text: string) => createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
  const manifest = entries.find(e => e.name === "manifest.json");
  if (manifest) {
    try {
      const parsed = JSON.parse(manifest.content) as { fileHashes?: Record<string, string>; fileSizes?: Record<string, number>; parserName?: string };
      for (const [file, hash] of Object.entries(parsed.fileHashes ?? {})) {
        const entry = entries.find(e => e.name === file);
        if (!entry) problems.push("ZIP_MANIFEST_FILE_MISSING " + file);
        else if (sha(entry.content) !== hash) problems.push("ZIP_MANIFEST_HASH_MISMATCH " + file);
        else if (parsed.fileSizes && parsed.fileSizes[file] !== Buffer.byteLength(entry.content, "utf8")) problems.push("ZIP_MANIFEST_SIZE_MISMATCH " + file);
      }
      for (const entry of entries) if (/^customized_/.test(entry.name) && !(entry.name in (parsed.fileHashes ?? {}))) problems.push("ZIP_FILE_NOT_IN_MANIFEST " + entry.name);
    } catch { problems.push("ZIP_MANIFEST_UNREADABLE"); }
  }
  return { entries, problems };
}
