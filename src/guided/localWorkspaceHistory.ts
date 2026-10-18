import {FORMATS,type MappingRule,type ParserDraft} from '../model';

/**
 * User-owned, origin-scoped browser experiment snapshots.
 * No fetch, backend endpoint, server storage, telemetry or LLM API calls.
 */
export const LOCAL_VERSION_DB='parser-studio-user-experiments-v1';
export const LOCAL_VERSION_LIMIT=30;
const TABLE='versions';
const MAX_SOURCE_BYTES=65536;
const MAX_RECORD_BYTES=180000;
const MAX_ALL_BYTES=4*1024*1024;
const safeName=/^[^\u0000-\u001f\u007f]{1,80}$/;
const hexSha=/^[a-f0-9]{64}$/;

export interface LocalVersion{
  contract:'parser-studio.browser-version.v1';
  id:string;
  label:string;
  createdAt:string;
  datasetName:string;
  source:string;
  draft:ParserDraft;
  sha256:string;
}

export interface LocalWorkingCopy{
  datasetName:string;
  source:string;
  draft:ParserDraft;
}

export interface VersionList{
  versions:LocalVersion[];
  rejected:number;
}

export interface VersionComparison{
  sourceChanged:boolean;
  changedLines:number;
  draftChanged:boolean;
  addedMappings:string[];
  removedMappings:string[];
  editedMappings:string[];
  changes:string[];
}

const encode=(s:string)=>new TextEncoder().encode(s);
const byteSize=(s:string)=>encode(s).length;
const json=(value:unknown)=>JSON.stringify(value);
const isObject=(v:unknown):v is Record<string,unknown> =>
  !!v&&typeof v==='object'&&!Array.isArray(v);
function digest(payload:string):Promise<string>{
  if(!globalThis.crypto?.subtle)throw Error('Secure browser hashing is unavailable.');
  return crypto.subtle.digest('SHA-256',encode(payload)).then(data=>
    Array.from(new Uint8Array(data),value=>value.toString(16).padStart(2,'0')).join(''));
}
function validMapping(value:unknown):value is MappingRule{
  if(!isObject(value))return false;
  return ['id','source','target'].every(k=>
    typeof value[k]==='string' && (value[k] as string).length>0&&
    (value[k] as string).length<=160)&&
    ['string','integer','number','boolean','ip','port','timestamp'].includes(String(value.type));
}
function safeNested(value:unknown,depth=0):boolean{
  if(depth>20)return false;
  if(value===null||typeof value==='string'||typeof value==='boolean')return true;
  if(typeof value==='number')return Number.isFinite(value);
  if(Array.isArray(value))return value.length<=500&&
    value.every(v=>safeNested(v,depth+1));
  if(!isObject(value)||Object.keys(value).length>200)return false;
  return Object.entries(value).every(([k,v])=>
    !['__proto__','prototype','constructor'].includes(k)&&
    k.length<=160&&safeNested(v,depth+1));
}
export function validLocalDraft(value:unknown):value is ParserDraft{
  if(!isObject(value))return false;
  if(!['name','vendor','pattern','csvColumns'].every(k=>
    typeof value[k]==='string'&&(value[k] as string).length<=8192))return false;
  if(!FORMATS.includes(value.format as typeof FORMATS[number])||
     !Array.isArray(value.mappings)||value.mappings.length>100||
     !value.mappings.every(validMapping))return false;
  if(value.guided!==undefined&&!isObject(value.guided))return false;
  const mappings=value.mappings as MappingRule[];
  if(new Set(mappings.map(m=>m.id)).size!==mappings.length)return false;
  return safeNested(value);
}
function snapshotContent(v:Omit<LocalVersion,'sha256'>):string{
  return json([v.contract,v.id,v.label,v.createdAt,v.datasetName,v.source,v.draft]);
}
function validateWorking(copy:LocalWorkingCopy,label:string){
  if(!safeName.test(label.trim())||typeof copy.datasetName!=='string'||
     byteSize(copy.datasetName)>256||typeof copy.source!=='string'||
     byteSize(copy.source)>MAX_SOURCE_BYTES||!validLocalDraft(copy.draft))
    throw Error('Local version is invalid or exceeds the bounded browser workspace limits.');
  if(byteSize(json(copy))>MAX_RECORD_BYTES)
    throw Error('Local version exceeds 180 KB. Reduce the sample or parser rules.');
}

export async function prepareLocalVersion(copy:LocalWorkingCopy,label:string):Promise<LocalVersion>{
  validateWorking(copy,label);
  const entry:Omit<LocalVersion,'sha256'>={
    contract:'parser-studio.browser-version.v1',
    id:crypto.randomUUID(),label:label.trim(),
    createdAt:new Date().toISOString(),
    datasetName:copy.datasetName,
    source:copy.source,
    draft:structuredClone(copy.draft),
  };
  return {...entry,sha256:await digest(snapshotContent(entry))};
}
export async function verifyLocalVersion(v:unknown):Promise<boolean>{
  if(!isObject(v)||v.contract!=='parser-studio.browser-version.v1'||
     typeof v.id!=='string'||!/^[a-f0-9-]{36}$/i.test(v.id)||
     typeof v.createdAt!=='string'||Number.isNaN(Date.parse(v.createdAt))||
     typeof v.label!=='string'||typeof v.sha256!=='string'||
     !hexSha.test(v.sha256))return false;
  try{
    const value=v as unknown as LocalVersion;
    validateWorking({datasetName:value.datasetName,source:value.source,draft:value.draft},value.label);
    if(byteSize(json(value))>MAX_RECORD_BYTES)return false;
    return value.sha256===await digest(snapshotContent(value));
  }catch{return false;}
}

function openDb():Promise<IDBDatabase>{
  return new Promise((resolve,reject)=>{
    if(typeof indexedDB==='undefined'){
      reject(Error('IndexedDB is unavailable in this browser.'));return;
    }
    const req=indexedDB.open(LOCAL_VERSION_DB,1);
    req.onupgradeneeded=()=>{
      const database=req.result;
      if(!database.objectStoreNames.contains(TABLE)){
        database.createObjectStore(TABLE,{keyPath:'id'});
      }
    };
    req.onerror=()=>reject(Error('Browser-only history could not be opened.'));
    req.onblocked=()=>reject(Error('Close other tabs of this site and retry local history.'));
    req.onsuccess=()=>{
      req.result.onversionchange=()=>req.result.close();
      resolve(req.result);
    };
  });
}
function readAll(db:IDBDatabase):Promise<unknown[]>{
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(TABLE,'readonly');
    const req=tx.objectStore(TABLE).getAll();
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(Error('Browser-local versions could not be read.'));
    tx.onabort=()=>reject(Error('Browser-local storage transaction was interrupted.'));
  });
}
export async function listLocalVersions():Promise<VersionList>{
  const db=await openDb();
  try{
    const stored=await readAll(db);
    const versions:LocalVersion[]=[];
    let rejected=0;
    for(const row of stored){
      if(await verifyLocalVersion(row))versions.push(row as LocalVersion);
      else rejected++;
    }
    versions.sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
    return {versions,rejected};
  }finally{db.close();}
}
export async function saveLocalVersion(copy:LocalWorkingCopy,label:string):Promise<LocalVersion>{
  const revision=await prepareLocalVersion(copy,label);
  const db=await openDb();
  try{
    return await new Promise<LocalVersion>((resolve,reject)=>{
      const tx=db.transaction(TABLE,'readwrite');
      const all=tx.objectStore(TABLE).getAll();
      let error:Error|null=null;
      all.onsuccess=()=>{
        const rows=all.result as unknown[];
        if(rows.length>=LOCAL_VERSION_LIMIT||
           rows.reduce<number>((n,row)=>n+byteSize(json(row)),0)+byteSize(json(revision))>MAX_ALL_BYTES){
          error=Error('Local history is full. Delete an unneeded version before saving.');
          tx.abort();return;
        }
        tx.objectStore(TABLE).add(revision);
      };
      tx.oncomplete=()=>resolve(revision);
      tx.onerror=()=>reject(error??Error('Browser storage is unavailable or its quota was exceeded.'));
      tx.onabort=()=>reject(error??Error('Local save failed. Your working copy was not changed.'));
    });
  }finally{db.close();}
}
export async function deleteLocalVersion(id:string):Promise<void>{
  if(!/^[a-f0-9-]{36}$/i.test(id))throw Error('Invalid local version identifier.');
  const db=await openDb();
  try{
    return await new Promise<void>((resolve,reject)=>{
      const tx=db.transaction(TABLE,'readwrite');
      tx.objectStore(TABLE).delete(id);
      tx.oncomplete=()=>resolve();
      tx.onerror=()=>reject(Error('Browser-local deletion failed.'));
      tx.onabort=()=>reject(Error('Browser-local deletion was interrupted.'));
    });
  }finally{db.close();}
}
export async function readLocalVersion(id:string):Promise<LocalVersion>{
  if(!/^[a-f0-9-]{36}$/i.test(id))throw Error('Invalid local version identifier.');
  const db=await openDb();
  let value:unknown;
  try{
    value=await new Promise((resolve,reject)=>{
      const tx=db.transaction(TABLE,'readonly');
      const req=tx.objectStore(TABLE).get(id);
      req.onsuccess=()=>resolve(req.result);
      req.onerror=()=>reject(Error('Could not read browser-local version.'));
    });
  }finally{db.close();}
  if(!(await verifyLocalVersion(value)))
    throw Error('Saved version is missing, corrupt, or has an invalid checksum.');
  return structuredClone(value as LocalVersion);
}
export function sameLocalWorking(a:LocalWorkingCopy,b:LocalWorkingCopy):boolean{
  return a.source===b.source&&a.datasetName===b.datasetName&&
    json(a.draft)===json(b.draft);
}
export function compareLocalVersions(a:LocalWorkingCopy,b:LocalWorkingCopy):VersionComparison{
  const first=new Map(a.draft.mappings.map(m=>[m.id,m]));
  const second=new Map(b.draft.mappings.map(m=>[m.id,m]));
  const addedMappings=[...second.keys()].filter(id=>!first.has(id));
  const removedMappings=[...first.keys()].filter(id=>!second.has(id));
  const editedMappings=[...first.keys()].filter(id=>
    second.has(id)&&json(first.get(id))!==json(second.get(id)));
  const changes:string[]=[];
  if(a.datasetName!==b.datasetName)changes.push('Dataset name');
  if(a.draft.vendor!==b.draft.vendor||a.draft.name!==b.draft.name||
     a.draft.version!==b.draft.version)changes.push('Parser identity');
  if(a.draft.format!==b.draft.format)changes.push('Parser format');
  if(a.draft.pattern!==b.draft.pattern)changes.push('Extraction pattern');
  if(a.draft.csvColumns!==b.draft.csvColumns||
     a.draft.csvDelimiter!==b.draft.csvDelimiter)changes.push('CSV schema / delimiter');
  if(json(a.draft.guided?.eventBoundary)!==json(b.draft.guided?.eventBoundary))
    changes.push('Event boundary');
  if(json(a.draft.guided?.receiver)!==json(b.draft.guided?.receiver))
    changes.push('Receiver / framing settings');
  if(json(a.draft.guided?.enrichment)!==json(b.draft.guided?.enrichment))
    changes.push('Enrichment rules');
  if(addedMappings.length||removedMappings.length||editedMappings.length)
    changes.push('Field mappings');
  const left=a.source.split('\n'),right=b.source.split('\n');
  let changedLines=0;
  for(let i=0;i<Math.max(left.length,right.length);i++)
    if(left[i]!==right[i])changedLines++;
  return {
    sourceChanged:a.source!==b.source,changedLines,
    draftChanged:json(a.draft)!==json(b.draft),
    addedMappings,removedMappings,editedMappings,changes,
  };
}
