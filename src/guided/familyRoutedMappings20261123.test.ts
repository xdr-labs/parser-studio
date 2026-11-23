import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {validateEventProfiles} from './multiEventRouting';
import {toBackendProject} from './backendAdapter';

// Audit G-09: PAN-OS and CEF in one sample read the source address from two different paths
// (generic.fields.src and body.src). One shared mapping cannot hold both, so the automatic draft mapped
// neither. Each event family now gets its own mappings, selected by the reading mode of the event.
// SYNTHETIC lines written after the documented formats (not vendor originals).
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const PAN_EXPECTED={srcip:'10.10.20.15',dstip:'8.8.8.8',srcport:'51514',dstport:'443'};
const CEF_EXPECTED={srcip:'10.0.0.7',dstip:'10.0.0.8',srcport:'51234',dstport:'443'};

function official(draft:ParserDraft,raw:string):Array<Record<string,string>>{
  const suite=preview(raw,draft);
  expect(suite.counts.failures).toBe(0);
  expect(suite.events.flatMap(event=>event.diagnostics.map(item=>item.code))).not.toContain('NO_MAPPINGS');
  return suite.events.map(event=>{
    const out=event.normalized as Record<string,unknown>;
    return Object.fromEntries(['srcip','dstip','srcport','dstport'].filter(key=>key in out).map(key=>[key,String(out[key])]));
  });
}
function build(lines:string[]){
  const built=buildAutomaticGenericStructuralDraft(lines.join('\n'),createDraft());
  expect(built).not.toBeNull();
  return built!;
}

describe('a sample of two event families maps each family from its own source paths (G-09)',()=>{
  for(const [name,lines,expected] of [
    ['PAN-OS then CEF',[PAN,CEF],[PAN_EXPECTED,CEF_EXPECTED]],
    ['CEF then PAN-OS',[CEF,PAN],[CEF_EXPECTED,PAN_EXPECTED]],
    ['PAN-OS, CEF, PAN-OS',[PAN,CEF,PAN.replace('10.10.20.15','10.10.20.16')],
      [PAN_EXPECTED,CEF_EXPECTED,{...PAN_EXPECTED,srcip:'10.10.20.16'}]],
  ] as const){
    it(name,()=>{
      const built=build([...lines]);
      expect(built.draft.eventProfiles?.discriminator).toBe('generic.mode');
      expect(validateEventProfiles(built.draft.eventProfiles)).toBeNull();
      // No mapping is shared by every family here; the families still compile (backend rule: a project
      // with event profiles may have no shared destination).
      const converted=toBackendProject(built.draft);
      expect(converted.ok,JSON.stringify(converted)).toBe(true);
      expect(official(built.draft,lines.join('\n'))).toEqual(expected);
    });
  }
  it('no event family holds one destination twice, and no event gets a value of another event',()=>{
    const built=build([PAN,CEF]);
    const shared=new Set(built.draft.mappings.map(mapping=>mapping.target));
    for(const variant of built.draft.eventProfiles!.variants){
      const targets=variant.mappings.map(mapping=>mapping.target);
      expect(new Set(targets).size).toBe(targets.length);
      expect(targets.filter(target=>shared.has(target))).toEqual([]);
    }
    const [pan,cef]=official(built.draft,[PAN,CEF].join('\n'));
    expect(Object.values(pan!).some(value=>CEF.includes(value)&&!PAN.includes(value))).toBe(false);
    expect(Object.values(cef!).some(value=>PAN.includes(value)&&!CEF.includes(value))).toBe(false);
  });
  it('an event family that was not in the sample is reported, not parsed with the mappings of another family',()=>{
    const built=build([PAN,CEF]);
    const other='<14>Oct 15 00:03:22 PA-FW01 {"srcip":"10.9.9.9","action":"allow"}';
    const suite=preview([PAN,other,CEF].join('\n'),built.draft);
    expect(suite.events.map(event=>event.parseStatus)).toEqual(['FULL','FULL','FULL']);
    expect(suite.events[1]!.diagnostics.map(item=>item.code)).toContain('UNRECOGNIZED_EVENT_FAMILY');
    expect(official(built.draft,[PAN,CEF].join('\n'))).toEqual([PAN_EXPECTED,CEF_EXPECTED]);
  });
});

describe('samples that one set of mappings already serves keep one set of mappings',()=>{
  const THREAT='<14>Oct 15 00:03:25 PA-FW01 1,2026/10/15 00:03:25,012345678901,THREAT,url,2561,2026/10/15 00:03:25,10.10.20.15,203.0.113.50,203.0.113.10,203.0.113.50,allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:25,123457,1,51520,80,62002,80,0x408000,tcp,alert,"example.com/index.html",(9999),computer-and-internet-info,informational,client-to-server,987654322,0x0,10.0.0.0-10.255.255.255,United States,0,text/html';
  it('PAN-OS TRAFFIC and THREAT share the endpoint mappings; a family-specific decision stays in its family',()=>{
    const built=buildAutomaticGenericStructuralDraft([PAN,THREAT].join('\n'),createDraft())!;
    const groups=built.draft.guided!.groups!;
    const official=(rules:readonly {id:string;source:string;target:string}[])=>
      rules.filter(rule=>groups[rule.id]!=='vendor_fields').map(rule=>rule.source+'>'+rule.target);
    expect(official(built.draft.mappings)).toEqual(expect.arrayContaining([
      'generic.fields.src>srcip','generic.fields.dst>dstip','generic.fields.sport>srcport','generic.fields.dport>dstport']));
    const all=[...built.draft.mappings,...(built.draft.eventProfiles?.variants.flatMap(variant=>variant.mappings)??[])];
    expect(official(all).filter(item=>item.endsWith('>direction'))).toEqual([]);
    const threat=built.draft.eventProfiles?.variants.find(variant=>variant.name==='panos_threat_csv');
    expect(official(threat?.mappings??[]).filter(item=>item.endsWith('>action'))).toEqual([]);   // 'alert' is no disposition
  });
  for(const [name,lines] of [['PAN-OS alone',[PAN]],['CEF alone',[CEF,CEF.replace('10.0.0.7','10.0.0.9')]]] as const){
    it(name,()=>{
      const built=buildAutomaticGenericStructuralDraft(lines.join('\n'),createDraft());
      if(built)expect(built.draft.eventProfiles).toBeUndefined();
    });
  }
});
