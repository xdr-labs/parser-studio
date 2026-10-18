/**
 * Operator-invoked OFFLINE preflight only.
 * No file creation, Ruby execution, customer-log echo, network or API routes.
 * It only reads one fixed private local file when an operator has created it.
 */
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
} from "node:fs";
import { resolve } from "node:path";
import {
  MAX_PRIVATE_GOLDEN_BYTES, inspectPrivateGolden, decodePrivateGoldenBytes,
} from "../src/private-golden.js";

class Refusal extends Error { constructor(readonly code:string) {super(code);} }

function readOperatorFile(): string {
  if (process.argv.length!==2) throw new Refusal("PRIVATE_ARGUMENTS_UNSUPPORTED");
  const uid=process.getuid?.();
  if(uid===undefined)throw new Refusal("PRIVATE_PLATFORM_UNSUPPORTED");
  const parent=resolve(".tmp");
  const parentStat=lstatSync(parent,{throwIfNoEntry:false});
  if (!parentStat || !parentStat.isDirectory() || parentStat.isSymbolicLink() ||
      parentStat.uid!==uid || (parentStat.mode & 0o022)!==0)
    throw new Refusal("PRIVATE_PARENT_UNSAFE");
  const root=resolve(parent,"private-fixtures");
  const file=resolve(root,"golden.json");
  const dirStat=lstatSync(root,{throwIfNoEntry:false});
  if (!dirStat) throw new Refusal("PRIVATE_DIRECTORY_MISSING");
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink() ||
      (dirStat.mode & 0o077)!==0 || dirStat.uid!==uid) {
    throw new Refusal("PRIVATE_DIRECTORY_UNSAFE");
  }
  const fileStat=lstatSync(file,{throwIfNoEntry:false});
  if (!fileStat)throw new Refusal("PRIVATE_FILE_MISSING");
  if (!fileStat.isFile() || fileStat.isSymbolicLink() ||
      fileStat.nlink!==1 || (fileStat.mode & 0o077)!==0 ||
      fileStat.uid!==uid || fileStat.size>MAX_PRIVATE_GOLDEN_BYTES) {
    throw new Refusal("PRIVATE_FILE_UNSAFE");
  }
  if (typeof constants.O_NOFOLLOW!=="number")throw new Refusal("PRIVATE_NOFOLLOW_UNAVAILABLE");
  const fd=openSync(file,constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened=fstatSync(fd);
    if (!opened.isFile() || opened.nlink!==1 ||
        opened.uid!==uid || (opened.mode & 0o077)!==0 ||
        opened.size>MAX_PRIVATE_GOLDEN_BYTES)throw new Refusal("PRIVATE_FILE_UNSAFE");
    return decodePrivateGoldenBytes(readFileSync(fd));
  }finally{
    closeSync(fd);
  }
}

try {
  const payload:unknown=JSON.parse(readOperatorFile());
  const outcome=inspectPrivateGolden(payload);
  if (!outcome.ok) {
    // Only static diagnostic codes + numeric JSON pointers. No supplied values.
    for (const issue of outcome.issues.slice(0,16)) {
      console.error("PRIVATE_PREFLIGHT_"+issue.code+" "+issue.path);
    }
    process.exitCode=2;
  }else{
    console.log("PRIVATE_PREFLIGHT_OK cases="+outcome.caseCount+
      " profiles="+outcome.profileCount+" native=false target=false");
  }
}catch(error){
  const code=error instanceof Refusal ? error.code :
    error instanceof Error && error.message==="PRIVATE_INVALID_UTF8" ? "PRIVATE_INVALID_UTF8" :
    "INVALID_OR_UNAVAILABLE";
  console.error("PRIVATE_PREFLIGHT_"+code);
  process.exitCode=2;
}
