/**
 * Deterministic, immutable download bundle for reviewed internally generated
 * Ruby + CONF pairs. No network, credentials, timestamps, or target writes.
 * ZIP STORE (no compression) uses one fixed manifest and two exact input files.
 */
import {createHash} from "node:crypto";
import {inspectPair} from "./import.js";
import {hasValidUnicodeJson} from "./unicode.js";
import type {ExportFile,PairExport} from "./types.js";

const sha256=(bytes:Buffer|string)=>createHash("sha256").update(bytes).digest("hex");
const FILE_NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const MAX_ARTIFACT_BYTES=2*1024*1024;
export class ArtifactPackageError extends Error {
  constructor(readonly code:string){super(code);this.name="ArtifactPackageError";}
}
function invalid(code:string):never{throw new ArtifactPackageError(code);}

export type ArtifactRevisionManifest={
  contract:"host-customized-pair-package.v0.1";
  status:"DRAFT";
  artifactRevisionId:string;
  version:string;
  parserName:string;
  projectId:string;
  projectRevision:number;
  schemaRevision:"0.1";
  selectedParserPort:number;
  receiverProtocols:readonly ("udp"|"tcp")[];
  fileHashes:Record<string,string>;
  fileSizes:Record<string,number>;
  engineVerified:false;
  runtimeParsingVerified:false;
  targetImportVerified:false;
  deploymentPerformed:false;
};
export type ArtifactPackage={
  zip:Buffer;
  zipSha256:string;
  filename:string;
  manifest:ArtifactRevisionManifest;
};

// Standard CRC-32 and ZIP32 (method STORE); entries are ASCII safe names
// and UTF-8 document bodies. No ZIP64, symlinks, external paths or timestamps.
const table=Array.from({length:256},(_,i)=>{
  let value=i;
  for(let step=0;step<8;step++)
    value=(value&1)?(0xedb88320^(value>>>1)):(value>>>1);
  return value>>>0;
});
function crc32(buffer:Buffer):number{
  let crc=0xffffffff;
  for(const byte of buffer)crc=table[(crc^byte)&255]!^(crc>>>8);
  return (crc^0xffffffff)>>>0;
}
function zipStored(entries:readonly {name:string;bytes:Buffer}[]):Buffer{
  const output:Buffer[]=[];
  const directory:Buffer[]=[];
  let position=0;
  for(const entry of entries){
    if(!/^[A-Za-z0-9_.-]{1,96}$/.test(entry.name) ||
      entry.bytes.length>MAX_ARTIFACT_BYTES)invalid("ARTIFACT_ZIP_ENTRY_INVALID");
    const name=Buffer.from(entry.name,"ascii");
    const crc=crc32(entry.bytes);
    const local=Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50,0);
    local.writeUInt16LE(20,4);
    local.writeUInt16LE(0,6); // flags
    local.writeUInt16LE(0,8); // STORE: exact uncompressed file bytes
    local.writeUInt16LE(0,10); // deterministic midnight timestamp
    local.writeUInt16LE(0x21,12); // 1980-01-01
    local.writeUInt32LE(crc,14);
    local.writeUInt32LE(entry.bytes.length,18);
    local.writeUInt32LE(entry.bytes.length,22);
    local.writeUInt16LE(name.length,26);
    output.push(local,name,entry.bytes);

    const central=Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50,0);
    central.writeUInt16LE(20,4);
    central.writeUInt16LE(20,6);
    central.writeUInt16LE(0,8);
    central.writeUInt16LE(0,10);
    central.writeUInt16LE(0,12);
    central.writeUInt16LE(0x21,14);
    central.writeUInt32LE(crc,16);
    central.writeUInt32LE(entry.bytes.length,20);
    central.writeUInt32LE(entry.bytes.length,24);
    central.writeUInt16LE(name.length,28);
    central.writeUInt32LE(0,38); // external attributes
    central.writeUInt32LE(position,42);
    directory.push(central,name);
    position+=local.length+name.length+entry.bytes.length;
  }
  const centralBytes=Buffer.concat(directory);
  const end=Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50,0);
  end.writeUInt16LE(entries.length,8);
  end.writeUInt16LE(entries.length,10);
  end.writeUInt32LE(centralBytes.length,12);
  end.writeUInt32LE(position,16);
  const total=Buffer.concat([...output,centralBytes,end]);
  if(total.length>MAX_ARTIFACT_BYTES)invalid("ARTIFACT_ZIP_TOO_LARGE");
  return total;
}

/** Verifies the exact submitted pair against current reviewed compiler output. */
export function buildArtifactPackage(pair:PairExport,version:string):ArtifactPackage{
  if(typeof version!=="string"||!VERSION.test(version))invalid("ARTIFACT_VERSION_INVALID");
  if(!pair||pair.contract!=="host-customized-pair.v0.1"||
    !pair.manifest||pair.manifest.contract!==pair.contract||
    pair.manifest.status!=="DRAFT"||pair.manifest.engineVerified!==false||
    pair.manifest.targetImportVerified!==false||
    pair.manifest.schemaRevision!=="0.1"||
    !Array.isArray(pair.files)||pair.files.length!==2)
    invalid("ARTIFACT_MANIFEST_INVALID");
  if(!hasValidUnicodeJson(pair))invalid("ARTIFACT_UNICODE_INVALID");
  const parser=pair.files.find(file=>typeof file?.name==="string"&&FILE_NAME.test(file.name));
  if(!parser)invalid("ARTIFACT_FILE_INVALID");
  const conf=pair.files.find(file=>file?.name===parser.name+".conf");
  if(!conf||new Set(pair.files.map(f=>f.name)).size!==2)
    invalid("ARTIFACT_FILE_INVALID");
  const files=[parser,conf];
  if(files.some(f=>typeof f.content!=="string"||!SHA.test(f.sha256)||
      Buffer.byteLength(f.content,"utf8")!==f.bytes||
      sha256(f.content)!==f.sha256||
      f.bytes<=0||f.bytes>MAX_ARTIFACT_BYTES))
    invalid("ARTIFACT_FILE_INTEGRITY");
  if(Object.keys(pair.manifest.fileHashes??{}).length!==2||
    files.some(f=>pair.manifest.fileHashes[f.name]!==f.sha256))
    invalid("ARTIFACT_MANIFEST_HASH");
  const check=inspectPair({name:parser.name,fragmentContent:parser.content,
    confContent:conf.content});
  if(check.importStatus!=="EDITABLE_EXACT"||!check.portableProject)
    invalid("ARTIFACT_NOT_REPRODUCIBLE");
  const project=check.portableProject;
  if(pair.manifest.projectId!==project.projectId||
    pair.manifest.projectRevision!==project.revision ||
    check.receiver.ports.length!==1||
    check.receiver.ports[0]!==project.receiver.port ||
    check.receiver.sourceCount!==project.receiver.protocols.length)
    invalid("ARTIFACT_REVISION_MISMATCH");
  const fileHashes=Object.fromEntries(files.map(f=>[f.name,f.sha256])) as Record<string,string>;
  const fileSizes=Object.fromEntries(files.map(f=>[f.name,f.bytes])) as Record<string,number>;
  const id=sha256(JSON.stringify({
    contract:"host-customized-pair-package.v0.1",
    schemaRevision:"0.1",projectId:project.projectId,projectRevision:project.revision,
    version,selectedParserPort:project.receiver.port,
    receiverProtocols:project.receiver.protocols,fileHashes,fileSizes,
  }));
  const manifest:ArtifactRevisionManifest={
    contract:"host-customized-pair-package.v0.1",
    status:"DRAFT",artifactRevisionId:id,
    version,parserName:parser.name,
    projectId:project.projectId,projectRevision:project.revision,
    schemaRevision:"0.1",selectedParserPort:project.receiver.port,
    receiverProtocols:[...project.receiver.protocols],fileHashes,fileSizes,
    engineVerified:false,runtimeParsingVerified:false,
    targetImportVerified:false,deploymentPerformed:false,
  };
  const manifestText=JSON.stringify(manifest,null,2)+"\n";
  const zip=zipStored([
    {name:parser.name,bytes:Buffer.from(parser.content,"utf8")},
    {name:conf.name,bytes:Buffer.from(conf.content,"utf8")},
    {name:"manifest.json",bytes:Buffer.from(manifestText,"utf8")},
  ]);
  return {zip,zipSha256:sha256(zip),
    filename:parser.name+"-r"+project.revision+".zip",manifest};
}
