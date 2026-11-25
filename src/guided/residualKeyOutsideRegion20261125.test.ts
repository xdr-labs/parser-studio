/**
 * H-2 key rule when the Auto Parser already read the value behind the key (2026-11-25).
 *
 * The server analysis reports the text it could not read. In `...|sip=10.80.8.8|dip=203.0.113.80|...` it reads the
 * two addresses and reports `...|sip=` and `|dip=` as unparsed regions: the key ends a region, its value lies outside
 * every region. A recipe may keep a key as literal text before `=` when a capture of exactly that name follows, but
 * the rule looked only at captures that touch a region, so the keys `sip` and `dip` were counted as lost and a
 * lossless recipe for any key=value text with recognized values was refused. SYNTHETIC lines.
 */
import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {accountResidualRegions,locateResidualRegions} from './residualProvenance';

const LINE=(n:number,sip:string,dip:string)=>`2026-11-25T00:10:1${n}Z|sensor=ids-4|sip=${sip}|dip=${dip}|sport=1234${n}|dport=53|proto=UDP|alert=DNS tunneling`;
const SOURCE=[LINE(0,'10.80.8.8','203.0.113.80'),LINE(1,'10.80.8.9','203.0.113.81')].join('\n');
// The regions the server analysis reports for these lines: everything except the two addresses.
const RESIDUALS=(source:string)=>source.split('\n').map(line=>{
  const [head,rest]=line.split('|sip=');const [sip,tail]=rest!.split('|dip=');const dip=tail!.split('|')[0]!;
  void sip;return [head+'|sip=','|dip=',tail!.slice(dip.length)];
});
const PATTERN=String.raw`^(?<ts>\S+)\|sensor=(?<sensor>[^|]+)\|sip=(?<sip>[^|]+)\|dip=(?<dip>[^|]+)\|sport=(?<sport>\d+)\|dport=(?<dport>\d+)\|proto=(?<proto>[^|]+)\|alert=(?<alert>.+)$`;

function regexDraft(pattern:string,extra:Partial<ParserDraft>={}):ParserDraft{
  return {...createDraft(),format:'regex',pattern,preserveUnmapped:true,mappings:[],...extra} as ParserDraft;
}
function account(source:string,draft:ParserDraft){
  const lines=source.split('\n');
  const regions=RESIDUALS(source).map((values,index)=>locateResidualRegions(lines[index]!,values)!);
  return accountResidualRegions(source,draft,regions);
}

describe('a key whose value the Auto Parser already read',()=>{
  it('may stay literal before = when a capture of exactly that name keeps the value',()=>{
    const result=account(SOURCE,regexDraft(PATTERN));
    expect(result.events.map(event=>[event.method,event.required,event.missing])).toEqual([
      ['capture_spans',3,0],['capture_spans',3,0]]);
  });

  it('is lost when the capture behind it has another name',()=>{
    const result=account(SOURCE,regexDraft(PATTERN.replace('sip=(?<sip>','sip=(?<source>')));
    expect(result.events[0]).toMatchObject({missing:1,reason:'UNACCOUNTED_SOURCE'});
    const at=SOURCE.indexOf('sip=');
    expect(result.events[0]!.firstUnaccounted).toEqual({startByte:at,endByte:at+3});
  });

  it('is lost when the value behind it is not captured',()=>{
    const result=account(SOURCE,regexDraft(PATTERN.replace('sip=(?<sip>[^|]+)','sip=[^|]+')));
    expect(result.events[0]).toMatchObject({missing:1,reason:'UNACCOUNTED_SOURCE'});
  });

  it('is lost when its capture does not reach the final output',()=>{
    const mappings=['ts','sensor','dip','sport','dport','proto','alert'].map(name=>({id:'m_'+name,source:name,target:'v_'+name,type:'string'}));
    const result=account(SOURCE,regexDraft(PATTERN,{preserveUnmapped:undefined,mappings} as Partial<ParserDraft>));
    expect(result.events[0]!.missing).toBe(1);
  });

  it('is lost when its capture only borrows the output value of another capture with the same text',()=>{
    // Both addresses are equal and only dip is mapped: the single output value cannot stand for sip as well.
    const source=[LINE(0,'10.80.8.8','10.80.8.8'),LINE(1,'10.80.8.9','10.80.8.9')].join('\n');
    const mappings=['ts','sensor','dip','sport','dport','proto','alert'].map(name=>({id:'m_'+name,source:name,target:'v_'+name,type:'string'}));
    const result=account(source,regexDraft(PATTERN,{preserveUnmapped:undefined,mappings} as Partial<ParserDraft>));
    expect(result.events[0]!.missing).toBeGreaterThan(0);
  });
});
