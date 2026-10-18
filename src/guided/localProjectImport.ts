import type { ParserDraft } from '../model';
import { reconstructExactBackendDraft } from './pairProjectImport';

/**
 * Offline Project JSON review. No backend request, executable source, or
 * customer sample log is ever accepted. The complete model must round-trip
 * through the current vetted Guided Builder adapter without loss.
 */
export const MAX_PROJECT_JSON_BYTES=262144;
const SAFE_SLUG=/^[a-z][a-z0-9_]{2,47}$/;

export function reviewLocalProjectJson(bytes:Uint8Array):ParserDraft {
  // Cross-realm Uint8Array values are common in browser/worker tests.
  // ArrayBuffer.isView does not reject those the way instanceof does.
  if(!ArrayBuffer.isView(bytes) || bytes.BYTES_PER_ELEMENT!==1 ||
    bytes.byteLength===0 || bytes.byteLength>MAX_PROJECT_JSON_BYTES){
    throw new Error('Local project JSON must be a non-empty file at most 256 KiB.');
  }
  let value:unknown;
  try{
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    value=JSON.parse(text);
  }catch{
    throw new Error('Project JSON must be strictly valid UTF-8 JSON.');
  }
  const slug=value&&typeof value==='object'&&!Array.isArray(value)
    ?(value as Record<string,unknown>).slug:null;
  if(typeof slug!=='string'||!SAFE_SLUG.test(slug)){
    throw new Error('Project JSON contains an unsupported or unsafe parser slug.');
  }
  const converted=reconstructExactBackendDraft(value,'customized_'+slug);
  if(!converted){
    throw new Error('Project JSON cannot be restored without losing or changing source, normalized field, route or receiver semantics.');
  }
  return converted;
}
