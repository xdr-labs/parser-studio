/** Explicit opt-in local Multi-Pass source preview; no automatic source upload. */
export interface MultiPassSourcePreview {
 contract:'parser-studio.multipass-source-preview.v0.1';
 status:'SOURCE_PARSED'|'PARTIAL'|'RAW_ONLY'|'STRUCTURED_EMPTY';
 syntax:string;sourceSha256:string;sourceBytes:number;
 fields:Record<string,unknown>;
 spans:Array<{path:string;startByte:number;endByte:number}>;
 residuals:Array<{startByte:number;endByte:number}>;
 issues:string[];nativeVerified:false;targetVerified:false;
}
export async function requestMultiPassPreview(raw:string,requester:typeof fetch=fetch):Promise<MultiPassSourcePreview>{
 const size=new TextEncoder().encode(raw).byteLength;
 if(!size||size>65536)throw new Error('Source must be between 1 and 65536 UTF-8 bytes.');
 const response=await requester('/api/v1/multipass/preview',{method:'POST',
  headers:{'Content-Type':'application/json'},cache:'no-store',credentials:'same-origin',
  body:JSON.stringify({raw})});
 if(!response.ok)throw new Error('Multi-Pass preview is unavailable. No engine result was accepted.');
 const value=await response.json() as Partial<MultiPassSourcePreview>;
 if(value.contract!=='parser-studio.multipass-source-preview.v0.1'||
  !['SOURCE_PARSED','PARTIAL','RAW_ONLY','STRUCTURED_EMPTY'].includes(value.status??'')||
  value.nativeVerified!==false||value.targetVerified!==false||
  value.sourceBytes!==size||!value.fields||Array.isArray(value.fields)||
  !Array.isArray(value.spans)||!Array.isArray(value.residuals)||!Array.isArray(value.issues))
  throw new Error('Untrusted Multi-Pass response.');
 if(!/^[a-f0-9]{64}$/.test(value.sourceSha256??'')||!globalThis.crypto?.subtle)
  throw new Error('Unverified source identity.');
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
 const expected=[...new Uint8Array(digest)].map(n=>n.toString(16).padStart(2,'0')).join('');
 if(value.sourceSha256!==expected)throw new Error('Multi-Pass response source mismatch.');
 for(const item of [...value.spans,...value.residuals]){
  if(!Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>=item.endByte)
    throw new Error('Invalid Multi-Pass byte span.');
 }
 return value as MultiPassSourcePreview;
}
