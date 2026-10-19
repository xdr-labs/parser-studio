/** Bounded local screening for source containers that are intentionally not
 * in the downloadable parser's original wire-format grammar. This is NOT
 * vendor fingerprinting or source parsing: positive evidence only blocks
 * an unsupported DRAFT; absence of evidence never establishes compatibility.
 */
export interface SourceWitness {
  raw:string;
  events:readonly {preview:{issues:readonly string[]}}[];
}
export type OriginalContainerKind=
  |'SOURCE_REVIEW_ONLY'|'DOCKER_JSON_FILE'|'KUBERNETES_CRI'|'LINUX_AUDIT'
  |'W3C_DECLARED'|'ZEEK_DECLARED'|'RFC6587_OCTETS'
  |'JSON_TEXT_SEQUENCE'|'NUL_DELIMITED_SOURCE'|'JOURNAL_EXPORT';
export interface OriginalContainerGate {
  kind:OriginalContainerKind;
  proof:'QUALIFIED_SOURCE_PREVIEW'|'BOUNDED_LOCAL_SIGNATURE';
}
const isObject=(value:unknown):value is Record<string,unknown>=>
  !!value&&typeof value==='object'&&!Array.isArray(value);

function dockerFileMarker(raw:string):boolean{
  const first=raw.slice(0,4096).split('\n',1)[0]!;
  if(!first.startsWith('{')||first.length>4096)return false;
  let parsed:unknown;
  try{parsed=JSON.parse(first);}catch{return false;}
  if(!isObject(parsed)||typeof parsed.log!=='string')return false;
  // The log + stream + time triad is the general Docker json-file record
  // wrapper, not a manufacturer event. Incomplete time still requires review.
  return typeof parsed.stream==='string'&&
    (typeof parsed.time==='string'||parsed.stream==='stdout'||parsed.stream==='stderr');
}

/** Negative evidence is authoritative, but a positive/browser "JSON" guess
 * must never overrule an original transport/framing signature.
 */
export function originalContainerCompilerGate(
  source:string,witness?:SourceWitness|null,
):OriginalContainerGate|null{
  if(!source||new TextEncoder().encode(source).length>65536)return null;
  if(witness?.raw===source&&witness.events.some(event=>
    event.preview.issues.some(code=>code.startsWith('FRAMING_')||
      code.startsWith('SCHEMA_'))))
    return {kind:'SOURCE_REVIEW_ONLY',proof:'QUALIFIED_SOURCE_PREVIEW'};

  // Original transport evidence may appear after a different first log
  // type. Inspect bounded physical record starts, not only the very first
  // source character. This never removes or changes any original source byte.
  const raw=source.startsWith('\ufeff')?source.slice(1):source;
  if(raw.includes('\x00'))
    return {kind:'NUL_DELIMITED_SOURCE',proof:'BOUNDED_LOCAL_SIGNATURE'};
  for(const originalLine of raw.split('\n')){
    const line=originalLine.endsWith('\r')?
      originalLine.slice(0,-1):originalLine;
    if(!line)continue;
    if(line.startsWith('\x1e'))
      return {kind:'JSON_TEXT_SEQUENCE',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^(?:node=\S+[ \t]+)?type=[A-Z][A-Z0-9_]*[ \t]+msg=audit\(/.test(line))
      return {kind:'LINUX_AUDIT',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^\d{4}-\d\d-\d\dT\S+[ \t]+(?:stdout|stderr)[ \t]+[PF][ \t]/.test(line))
      return {kind:'KUBERNETES_CRI',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^(?:#Version:|#Software:|#Fields:)/.test(line))
      return {kind:'W3C_DECLARED',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^(?:#separator[ \t]|#fields\t)/.test(line))
      return {kind:'ZEEK_DECLARED',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^[1-9]\d{0,5} (?:<\d{1,3}>|\{|\[)/.test(line))
      return {kind:'RFC6587_OCTETS',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(/^(?:__CURSOR=|_BOOT_ID=|MESSAGE=)/.test(line)&&raw.includes('\n\n'))
      return {kind:'JOURNAL_EXPORT',proof:'BOUNDED_LOCAL_SIGNATURE'};
    if(dockerFileMarker(line))
      return {kind:'DOCKER_JSON_FILE',proof:'BOUNDED_LOCAL_SIGNATURE'};
  }
  return null;
}
