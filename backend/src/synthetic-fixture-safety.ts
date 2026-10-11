/** Fixed offline synthetic output boundary. Not an API for customer or vendor files. */
import {
  closeSync, constants, lstatSync, mkdirSync, openSync, realpathSync, writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(".tmp/native-fixtures");
const PARENT = resolve(".tmp");
const SYNTHETIC_FILE = /^customized_[a-z][a-z0-9_]{1,47}(?:\.conf)?$/;

function checkedDirectory(path: string): void {
  const existing = lstatSync(path, {throwIfNoEntry: false});
  if (existing && (!existing.isDirectory() || existing.isSymbolicLink())) {
    throw new Error("Unsafe synthetic fixture directory.");
  }
  if (!existing) mkdirSync(path, {mode:0o700});
  if (realpathSync(path) !== path) {
    throw new Error("Unsafe synthetic fixture directory symlink.");
  }
}

export function safeSyntheticOutputDirectory(override?: string): string {
  if (override !== undefined && resolve(override) !== ROOT) {
    throw new Error("Unsafe synthetic fixture directory override.");
  }
  checkedDirectory(PARENT);
  checkedDirectory(ROOT);
  return ROOT;
}

export function writeSyntheticFixture(directory: string, name: string, content: string): void {
  if (!SYNTHETIC_FILE.test(name)) {
    throw new Error("Invalid synthetic fixture filename.");
  }
  safeSyntheticOutputDirectory(directory);
  const file = resolve(ROOT, name);
  const old = lstatSync(file, {throwIfNoEntry:false});
  if (old && (!old.isFile() || old.isSymbolicLink() || old.nlink !== 1)) {
    throw new Error("Unsafe synthetic fixture file target.");
  }
  if (typeof constants.O_NOFOLLOW !== "number") {
    throw new Error("Safe synthetic fixture file creation is unavailable on this platform.");
  }
  const fd = openSync(file,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, content, {encoding:"utf8"});
  } finally {
    closeSync(fd);
  }
}
