import {describe,it,expect} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidates,suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

describe('official-catalog normalization candidates',()=>{
  it('recommends documented Stellar destinations with compatible source values',()=>{
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1',dst_port:443},[])).toEqual([
      expect.objectContaining({source:'src_ip',target:'srcip',type:'ip',confidence:'HIGH',
        catalogVerified:true,catalogRelease:'7.0.xs',group:'top_fields'}),
      expect.objectContaining({source:'dst_port',target:'dstport',type:'integer',confidence:'HIGH',
        catalogVerified:true,catalogRelease:'7.0.xs',group:'top_fields'}),
    ]);
  });
  it('proposes replacing generated custom mappings instead of duplicating their source',()=>{
    const existing=[{id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string' as const,
      authoring:{version:1 as const,origin:'AUTO' as const}}];
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},existing)).toEqual([
      expect.objectContaining({source:'src_ip',target:'srcip',replacesMappingId:'auto-1',
        currentTarget:'custom.src_ip',safeForBulk:true}),
    ]);
  });
  it('never treats an auto-looking ID as permission to override a manual edit',()=>{
    for(const origin of ['USER_EDITED','APPROVED'] as const){
      const existing=[{id:'auto-1',source:'src_ip',target:'custom.src_ip',
        type:'string' as const,authoring:{version:1 as const,origin}}];
      const candidate=suggestNormalizationCandidates({src_ip:'192.0.2.1'},existing)[0]!;
      expect(candidate).toMatchObject({target:'srcip',safeForBulk:false});
    }
    const legacy=[{id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string' as const}];
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},legacy)[0])
      .toMatchObject({target:'srcip',safeForBulk:false});
  });

  it('uses whole-sample type evidence and lowers confidence when one value disagrees',()=>{
    const suite={events:[
      {fields:{src_ip:'192.0.2.1'}},{fields:{src_ip:'not-an-ip'}},
    ]} as unknown as SuiteResult;
    expect(suggestNormalizationCandidatesFromSuite(suite,[])[0]).toMatchObject({
      source:'src_ip',confidence:'REVIEW',observed:2,total:2,safeForBulk:false,
    });
  });
  it('covers common AWS CloudTrail and WAF source address names without broad semantic guessing',()=>{
    expect(suggestNormalizationCandidates({sourceIPAddress:'198.51.100.10'},[])[0])
      .toMatchObject({source:'sourceIPAddress',target:'srcip',confidence:'HIGH'});
    expect(suggestNormalizationCandidates({httpRequest:{clientIp:'203.0.113.7'}},[])[0])
      .toMatchObject({source:'httpRequest.clientIp',target:'srcip',confidence:'HIGH'});
  });
  it('covers common CEF/LEEF and camel-case security field names only when values fit',()=>{
    const suggestions=suggestNormalizationCandidates({
      src:'192.0.2.10',dst:'198.51.100.20',spt:'51000',dpt:443,act:'blocked',
      sourceIp:'192.0.2.30',destinationIp:'198.51.100.30',
      sourcePort:52000,destinationPort:'8443',deviceName:'sensor-01',
    },[]);
    expect(suggestions).toEqual(expect.arrayContaining([
      // Same target appears under two source aliases; both require human review
      // instead of permitting order-dependent automatic normalization.
      expect.objectContaining({source:'src',target:'srcip',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'dst',target:'dstip',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'spt',target:'srcport',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'dpt',target:'dstport',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'act',target:'action',confidence:'HIGH'}),
      expect.objectContaining({source:'deviceName',target:'hostname',confidence:'HIGH'}),
    ]));
    expect(suggestNormalizationCandidates({src:'not-an-ip'},[])[0])
      .toMatchObject({source:'src',target:'srcip',confidence:'REVIEW',safeForBulk:false});
  });
  it('matches runtime type semantics for IPv6 and timezone-qualified timestamps',()=>{
    expect(suggestNormalizationCandidates({src_ip:'2001:db8::10'},[])[0])
      .toMatchObject({source:'src_ip',target:'srcip',confidence:'HIGH',safeForBulk:true});
    expect(suggestNormalizationCandidates({event_time:'2026-10-16T12:30:00Z'},[])[0])
      .toMatchObject({source:'event_time',target:'timestamp',confidence:'HIGH',safeForBulk:true});
    expect(suggestNormalizationCandidates({event_time:'2026-10-16T12:30:00'},[])[0])
      .toMatchObject({source:'event_time',target:'timestamp',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({dst_port:65536},[])[0])
      .toMatchObject({source:'dst_port',target:'dstport',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({severity:101},[])[0])
      .toMatchObject({source:'severity',target:'severity',confidence:'REVIEW',safeForBulk:false});
    expect(suggestNormalizationCandidates({severity:100},[])[0])
      .toMatchObject({source:'severity',target:'severity',confidence:'HIGH',safeForBulk:true});
  });
  it('uses the final segment of nested source paths while preserving the full source path',()=>{
    const suggestions=suggestNormalizationCandidates({
      parserstudio_source:{
        syslog:{host:'bigip-waf01',time:'00:14:27'},
        generic:{fields:{ip_client:'203.0.113.210',dest_ip:'10.20.1.25',dest_port:'443',protocol:'HTTPS'}},
      },
    },[]);
    expect(suggestions).toEqual(expect.arrayContaining([
      expect.objectContaining({source:'parserstudio_source.syslog.host',target:'hostname',confidence:'HIGH'}),
      expect.objectContaining({source:'parserstudio_source.generic.fields.ip_client',target:'srcip',confidence:'HIGH'}),
      expect.objectContaining({source:'parserstudio_source.generic.fields.dest_ip',target:'dstip',confidence:'HIGH'}),
      expect.objectContaining({source:'parserstudio_source.generic.fields.dest_port',target:'dstport',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'parserstudio_source.generic.fields.protocol',target:'proto_name',confidence:'REVIEW',safeForBulk:false}),
      expect.objectContaining({source:'parserstudio_source.syslog.time',target:'timestamp',confidence:'REVIEW'}),
    ]));
  });

  it('maps common EDR/XDR leaf names to documented Stellar scalar fields while leaving unknown semantics alone',()=>{
    const suggestions=suggestNormalizationCandidates({
      timestamp:'2026-10-15T00:07:33.425+09:00',
      eventType:'DetectionSummaryEvent',
      severity:80,
      severityName:'High',
      hostname:'WS-FINANCE-023',
      localIP:'10.30.5.23',
      userName:'CORP\\jsmith',
      processName:'powershell.exe',
      commandLine:'powershell.exe -NoProfile -EncodedCommand REDACTED',
      parentProcess:'WINWORD.EXE',
      sha256:'6f5902ac237024bdd0c176cb93063dc46f5902ac237024bdd0c176cb93063dc4',
      tactic:'Execution',technique:'PowerShell',techniqueId:'T1059.001',
      action:'Detection',
    },[]);
    expect(suggestions).toEqual(expect.arrayContaining([
      expect.objectContaining({source:'timestamp',target:'timestamp',confidence:'HIGH'}),
      expect.objectContaining({source:'severity',target:'severity',confidence:'HIGH'}),
      expect.objectContaining({source:'hostname',target:'hostname',confidence:'HIGH'}),
      expect.objectContaining({source:'localIP',target:'hostip',confidence:'HIGH'}),
      expect.objectContaining({source:'userName',target:'username',confidence:'HIGH'}),
      expect.objectContaining({source:'processName',target:'process_name',confidence:'HIGH'}),
      expect.objectContaining({source:'commandLine',target:'command',confidence:'HIGH'}),
      expect.objectContaining({source:'parentProcess',target:'parent_proc_name',confidence:'HIGH'}),
      expect.objectContaining({source:'sha256',target:'sha256',confidence:'HIGH'}),
    ]));
    // EDR event family and detection state are not Stellar ML event_type or enforcement action.
    expect(suggestions.some(item=>['eventType','action'].includes(item.source))).toBe(false);
    expect(suggestions.some(item=>['severityName','tactic','technique','techniqueId'].includes(item.source))).toBe(false);
  });

  it('abstains when another mapping owns the official destination',()=>{
    expect(suggestNormalizationCandidates({src_ip:'192.0.2.1'},[
      {id:'1',source:'x',target:'srcip',type:'ip'},
    ])).toEqual([]);
  });
  describe('Generic Structural space_kv trailing text',()=>{
    const generic=(kv:Record<string,string>,atoms:Record<string,string>)=>({generic:{mode:'space_kv',kv,atoms}});
    it('maps the first atom of a port value that absorbed trailing free text',()=>{
      const fields=generic(
        {protocol:'udp',sport:'55719',dport:'53 pattern: allow all'},
        {dport_001:'53',dport_002:'pattern:',dport_003:'allow',dport_004:'all'});
      const candidates=suggestNormalizationCandidates(fields,[]);
      expect(candidates).toContainEqual(expect.objectContaining({
        source:'generic.atoms.dport_001',target:'dstport',type:'integer',
        confidence:'HIGH',safeForBulk:true}));
      // The whole-value source stays reviewable but is never auto-approved.
      expect(candidates.find(item=>item.source==='generic.kv.dport'))
        .toMatchObject({confidence:'REVIEW',safeForBulk:false});
    });
    it('does not accept an atom whose own value is not a valid port',()=>{
      const fields=generic({dport:'abc def'},{dport_001:'abc',dport_002:'def'});
      const high=suggestNormalizationCandidates(fields,[]).filter(item=>item.confidence==='HIGH');
      expect(high.some(item=>item.target==='dstport')).toBe(false);
    });
    it('does not truncate free-text or timestamp values into official fields',()=>{
      const fields=generic(
        {time:'2026-01-01 10:00:00',msg:'53 apples',bytes:'1024 KB'},
        {time_001:'2026-01-01',time_002:'10:00:00',msg_001:'53',msg_002:'apples',
          bytes_001:'1024',bytes_002:'KB'});
      const high=suggestNormalizationCandidates(fields,[]).filter(item=>item.source.includes('atoms.'));
      expect(high).toEqual([]);
    });
    it('does not use a non-first atom as the port value',()=>{
      const fields=generic({dport:'x 53'},{dport_001:'x',dport_002:'53'});
      expect(suggestNormalizationCandidates(fields,[])
        .some(item=>item.source==='generic.atoms.dport_002')).toBe(false);
    });
  });
});
