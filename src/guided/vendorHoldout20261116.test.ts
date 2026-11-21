import {describe,expect,it} from 'vitest';
import {readFileSync,readdirSync} from 'node:fs';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {listSafeLeafPaths} from '../fieldPaths';
import type {BackendCapabilities} from './backendCapabilities';

// Holdout logs written from vendor log grammars (tests/fixtures/vendor-holdout-20261116). Each sample carries a
// semantic oracle that was written from the vendor grammar, not from a parser run: per event the Stellar meaning
// (canon), source values that must survive (values) and Stellar fields that would be a wrong mapping (forbid).
// The automatic draft may leave a meaning unmapped; it may never map it wrongly, lose a value, or mix events.
const ROOT='tests/fixtures/vendor-holdout-20261116/';
// The capabilities the backend of this tree serves (backend/test/vendor-holdout-capabilities.test.ts keeps the copy equal).
const cap=JSON.parse(readFileSync('tests/fixtures/vendor-holdout-capabilities-20261116.json','utf8')) as BackendCapabilities;
interface Oracle{canon:Record<string,unknown>;values:Record<string,unknown>;forbid:[string,unknown][]}
interface Meta{expect:'PARSE'|'ASSISTED';oracle:Oracle[]}

/** How the automatic journey reads each sample today, and how many expected Stellar meanings it maps correctly
 * (Stellar field present with the value of the oracle). A change of a line here is a change of behaviour to
 * review; a lower number is a lost mapping, such as the automatic mappings that read nothing for CEF lines. */
const READING:Record<string,[string,number]>={
  h_checkpoint_logexporter:['generic',6],
  h_cloudtrail_line:['json',2],
  h_fortigate_mixed:['generic',11],    // srcport, dstport, url: official names present in some record families only
  h_fortigate_webfilter:['generic',12],
  h_imperva_cef:['cef',1],
  h_okta_system_log:['json',1],
  h_panos_threat_url:['generic',1],
  h_panos_traffic:['generic',12],
  h_sonicwall_fw:['generic',0],
  h_sophos_xg_fw:['kv',8],
  h_srx_sd_close_deny:['syslog_rfc5424',13],
  h_stormshield_filter:['kv',6],
  h_suricata_rfc5424:['syslog_rfc5424',10],
  h_zeek_conn_json:['json',10],        // id.orig_h/id.resp_h/id.orig_p/id.resp_p are the conn.log endpoints; proto holds the name
  // Free text: a parsing rule is needed (ChatGPT Assisted Parser). Declined with a diagnosis, never guessed.
  h_cisco_asa_mixed:['declined',0],
  h_nginx_combined:['declined',0],
  h_pfsense_filterlog:['declined',0],
  h_sshd_auth:['declined',0],
  h_vpcflow_v2:['declined',0],
  // Vendor records the automatic journey does not read yet (docs/verification/20261116-accuracy-after-311.md).
  h_cisco_ftd_430003:['declined',0],   // "Key: value, Key: value" list behind %FTD-n-nnnnnn:
  h_cloudflare_http:['declined',0],    // nanosecond integers above 2^53
  h_meraki_urls_flows:['declined',0],  // a urls record has fewer than five key=value pairs
  h_trendmicro_ds_leef:['generic',5], // repository-authored Trend Micro grammar shape: implicit-TAB LEEF 2.0 behind RFC 3164
  h_win4625_nxlog_json:['declined',0], // Keywords is a 64-bit integer
};

function automaticDraft(raw:string):ParserDraft|null{
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(raw,'single-line');
  const native=prepareAutoParserDraft(raw,draft,preview(raw,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  if(native.ok)return native.draft;
  return ledger.unsupported>0?buildAutomaticGenericStructuralDraft(raw,draft)?.draft??null:null;
}
/** Every value of the output except the copies of the whole source text that the grammar keeps (source_raw,
 * message_raw): a value counts as kept when a field holds it, not when the raw line happens to contain it. */
function leaves(value:unknown,out:unknown[]=[]):unknown[]{
  if(Array.isArray(value))for(const item of value)leaves(item,out);
  else if(value!==null&&typeof value==='object'){
    for(const [key,item] of Object.entries(value))if(key!=='source_raw'&&key!=='message_raw')leaves(item,out);
  }else out.push(value);
  return out;
}
const same=(a:unknown,b:unknown)=>String(a)===String(b);
function kept(found:unknown[],value:unknown):boolean{
  const text=String(value);
  if(found.some(item=>same(item,value)||(typeof item==='string'&&item.includes(text))))return true;
  // A time mapped to the Stellar timestamp is kept when the output holds the same instant.
  const iso=/^\d{4}-\d{2}-\d{2}T/u;
  const instant=typeof value==='string'&&iso.test(value)?Date.parse(value):NaN;
  return !Number.isNaN(instant)&&found.some(item=>item===instant||(typeof item==='string'&&iso.test(item)&&Date.parse(item)===instant));
}

describe('vendor holdout logs: the automatic draft maps nothing wrongly and loses nothing',()=>{
  const samples=readdirSync(ROOT).sort();
  it('covers every sample of the fixture',()=>{
    expect(samples).toEqual(Object.keys(READING).sort());
  });
  for(const id of samples){
    it(id,()=>{
      const raw=readFileSync(ROOT+id+'/raw.log','utf8').replace(/\n+$/u,'');
      const meta=JSON.parse(readFileSync(ROOT+id+'/meta.json','utf8')) as Meta;
      const draft=automaticDraft(raw);
      const reading=draft===null?'declined':draft.format==='generic_structural'?'generic':draft.format;
      expect(reading).toBe(READING[id]![0]);
      if(draft===null)return;
      const suite=preview(raw,draft);
      // Every automatic mapping reads a field that some event of the sample has.
      const produced=new Set(suite.events.flatMap(event=>listSafeLeafPaths(event.fields)));
      expect(draft.mappings.filter(mapping=>!produced.has(mapping.source)).map(mapping=>mapping.source)).toEqual([]);
      let correct=0;
      expect(suite.events.length).toBe(meta.oracle.length);
      expect(suite.counts.failures).toBe(0);
      const lines=raw.split('\n');
      suite.events.forEach((event,index)=>{
        const oracle=meta.oracle[index]!;
        const output=event.normalized as Record<string,unknown>;
        const found=leaves(output);
        const problems:string[]=[];
        for(const [field,value] of Object.entries(oracle.canon)){
          if(!(field in output))continue;
          if(same(output[field],value))correct++;
          else problems.push('wrong '+field+'='+String(output[field])+', the event says '+String(value));
        }
        for(const [field,value] of oracle.forbid)
          if(field in output&&same(output[field],value))problems.push('forbidden '+field+'='+String(value));
        for(const [field,value] of [...Object.entries(oracle.canon),...Object.entries(oracle.values)])
          if(!kept(found,value))problems.push('lost '+field+'='+String(value));
        // No value of another event: a text value of this output that this line does not contain but another does.
        for(const item of found){
          if(typeof item!=='string'||item.length<4||lines[index]!.includes(item))continue;
          if(lines.some((line,other)=>other!==index&&line.includes(item)))problems.push('value of another event: '+item);
        }
        expect(problems,id+' event '+(index+1)).toEqual([]);
      });
      expect(correct,'Stellar meanings mapped correctly').toBe(READING[id]![1]);
    });
  }
});
