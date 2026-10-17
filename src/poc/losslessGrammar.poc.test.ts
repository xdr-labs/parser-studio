import {describe,expect,it} from 'vitest';
import {inspectGrammarFunnel,replayCandidate} from './grammarFunnel';
import {scanKeyValues,scanDelimitedRow,scanPrefixedKeyValues} from './losslessLexer';

function validByteSpans(raw:string,fields:NonNullable<ReturnType<typeof scanKeyValues>>['fields']){
  const encode=new TextEncoder();
  for(const field of fields){
    for(const range of [field.fieldSpan,field.valueSpan,field.rawValueSpan,...(field.keySpan?[field.keySpan]:[])]){
      expect(encode.encode(raw.slice(0,range.start)).length).toBe(range.startByte);
      expect(encode.encode(raw.slice(0,range.end)).length).toBe(range.endByte);
      expect(range.start).toBeLessThanOrEqual(range.end);
      expect(range.end).toBeLessThanOrEqual(raw.length);
    }
  }
}

describe('bounded, source-lossless lexical layer',()=>{
  it('preserves escaped values, source names, UTF-8 byte spans and quoted empty values',()=>{
    const raw='src_ip="198.51.100.3" note="Unicode 😀, escaped \\"mark\\"" status="" action=allow';
    const found=scanKeyValues(raw,0,'space');
    expect(found).not.toBeNull();
    expect(found!.fields.map(f=>[f.key,f.value])).toEqual([
      ['src_ip','198.51.100.3'],['note','Unicode 😀, escaped "mark"'],
      ['status',''],['action','allow'],
    ]);
    expect(found!.fields[1]!.valueSpan.endByte-found!.fields[1]!.valueSpan.startByte)
      .toBeGreaterThan(found!.fields[1]!.valueSpan.end-found!.fields[1]!.valueSpan.start);
    validByteSpans(raw,found!.fields);
    expect(replayCandidate(found!)).toMatchObject({
      fullBodyCovered:true,tokenSpansReplayed:true,sourceOracleVerified:false,
      fieldCount:4,naming:'source',
    });
    expect(found!.sourceRaw).toBe(raw);
  });

  it('second pass detects manipulated decoded values and source byte offsets',()=>{
    const raw='a="hello \\"quoted\\"" b=world';
    const candidate=scanKeyValues(raw,0,'space')!;
    expect(replayCandidate(candidate)).not.toBeNull();
    const wrongValue=structuredClone(candidate);
    wrongValue.fields[0]!.value='different';
    expect(replayCandidate(wrongValue)).toBeNull();
    const wrongSpan=structuredClone(candidate);
    wrongSpan.fields[0]!.valueSpan.start++;
    expect(replayCandidate(wrongSpan)).toBeNull();
    const wrongKey=structuredClone(candidate);
    wrongKey.fields[0]!.key='constructor';
    expect(replayCandidate(wrongKey)).toBeNull();

    const row=scanDelimitedRow('"first,second",7,"escaped ""quote"""',0,'comma')!;
    expect(replayCandidate(row)).not.toBeNull();
    const wrongCsv=structuredClone(row);
    wrongCsv.fields[0]!.value='first second';
    expect(replayCandidate(wrongCsv)).toBeNull();
  });

  it('reuses one tokenizer across whitespace, pipe, semicolon, tab and comma bodies',()=>{
    const cases=[
      ['space','a=1 b="two words" c=3'],
      ['pipe','a=1|b="two words"|c=3'],
      ['semicolon','a=1;b="two words";c=3'],
      ['tab','a=1\tb="two words"\tc=3'],
      ['comma','a=1,b="two words",c=3'],
    ] as const;
    for(const [delimiter,text] of cases){
      const result=scanKeyValues(text,0,delimiter);
      expect(result?.fields.map(x=>x.value)).toEqual(['1','two words','3']);
      expect(replayCandidate(result!)).not.toBeNull();
    }
  });

  it('abstains on unsafe names, collisions, malformed quote, partial consumption and size abuse',()=>{
    const invalid=[
      'a=1 a=2',
      'source-address=1 source_address=2',
      '__proto__=hacked other=1',
      'constructor=bad other=1',
      'a="unterminated b=2',
      'a=1 b="value"tail',
      'a=1 b=2 unexpected',
      'a=1;b=2;',
      'a=1 b=”typographic”',
      'a=1 b=unescaped"quote',
      'a=1 b=2\0',
      'a=1 b=2\n',
      'a=1 b=2\r',
      'a=1 b=2\uD800',
      'a='+ 'x'.repeat(17000)+' b=2',
    ];
    for(const raw of invalid)expect(scanKeyValues(raw,0,'space'),raw.slice(0,50)).toBeNull();
  });

  it('preserves an uninterpreted prefix rather than inventing a hostname or swallowing it',()=>{
    const raw='198.51.100.25  id=firewall time="2026-10-17 08:02:00 UTC" action=blocked';
    const result=scanPrefixedKeyValues(raw,0);
    expect(result?.prefixSpan).toMatchObject({start:0,end:15});
    expect(result?.fields.map(field=>field.value)).toEqual([
      'firewall','2026-10-17 08:02:00 UTC','blocked',
    ]);
    expect(replayCandidate(result!)).toMatchObject({
      tokenSpansReplayed:true,fullBodyCovered:false,sourceOracleVerified:false,
      unparsedPrefixBytes:15,
    });
    expect(inspectGrammarFunnel(raw)).toMatchObject({
      disposition:'partial_candidate',
      selected:{grammar:'prefixed_kv_space',fieldCount:3,sourceOracleVerified:false},
    });
  });

  it('preserves duplicate source field occurrences without overwriting values',()=>{
    const raw='msg="first" msg="second" action=deny';
    expect(scanKeyValues(raw,0,'space')).toBeNull();
    const preserved=scanKeyValues(raw,0,'space',{preserveRepeated:true});
    expect(preserved?.repeatedKeys).toEqual(['msg']);
    expect(preserved?.fields.map(f=>[f.key,f.value])).toEqual([
      ['msg','first'],['msg','second'],['action','deny'],
    ]);
    expect(inspectGrammarFunnel(raw)).toMatchObject({
      disposition:'partial_candidate',
      selected:{repeatedSourceKeys:1,fullBodyCovered:false,sourceOracleVerified:false},
    });
  });

  it('preserves quoted CSV cell syntax without inventing source column names',()=>{
    const raw='"one,part",42,"double ""quote""",😀';
    const found=scanDelimitedRow(raw,0,'comma');
    expect(found?.fields.map(x=>[x.key,x.value])).toEqual([
      ['column_1','one,part'],['column_2','42'],
      ['column_3','double "quote"'],['column_4','😀'],
    ]);
    expect(replayCandidate(found!)).toMatchObject({naming:'positional',sourceOracleVerified:false});
    validByteSpans(raw,found!.fields);
  });
});

describe('two-pass, accuracy-first candidate funnel',()=>{
  it('extracts generic field candidates behind verified Syslog envelope without overwriting baseline',()=>{
    const raw='<14>1 2026-10-17T08:01:02Z secgw app - - - src=192.0.2.1 dst=198.51.100.9 action=allow';
    const inspected=inspectGrammarFunnel(raw);
    expect(inspected.disposition).toBe('candidate_only');
    expect(inspected.passes).toBe(2);
    expect(inspected.selected).toMatchObject({
      grammar:'kv_space',fieldCount:3,fullBodyCovered:true,
      tokenSpansReplayed:true,sourceOracleVerified:false,
    });
    expect(inspected.bodyStart).toBeGreaterThan(0);
    const guarded=inspectGrammarFunnel(raw,true);
    expect(guarded.disposition).toBe('baseline_preserved');
    expect(guarded.selected).toBeNull();
  });

  it('prefers exact source-named columns over temporary positional CSV when interpretations agree',()=>{
    const outcome=inspectGrammarFunnel('src=192.0.2.1,dst=198.51.100.2,action=allow');
    expect(outcome.disposition).toBe('candidate_only');
    expect(outcome.selected).toMatchObject({grammar:'kv_comma',naming:'source',fieldCount:3});
  });

  it('abstains when two bounded named grammars produce contradictory fields',()=>{
    const outcome=inspectGrammarFunnel('a=1|b=2;c=3');
    expect(outcome.disposition).toBe('ambiguous');
    expect(outcome.selected).toBeNull();
    expect(outcome.candidates.filter(x=>x.naming==='source').length).toBeGreaterThanOrEqual(2);
  });

  it('refuses unrecognized or malformed outer Syslog timestamps',()=>{
    const malformed='<85>1 2023-01-13T10:10:16--5:00 example CP-GW - Log - src=192.0.2.1 dst=198.51.100.2';
    expect(inspectGrammarFunnel(malformed)).toMatchObject({
      disposition:'invalid_envelope',selected:null,candidates:[],
    });
  });

  it('never converts unsupported prose, JSON or malformed known vendor input into certified success',()=>{
    const examples=[
      '2026-10-17 10:01:00 Something strange happened in the firewall',
      '{"sensor":"suricata","alert":{"signature":"suspicious"}}',
      '<14>1 2026-10-17T08:01:02Z srx RT_FLOW - MSG [junos@1.2 src="bad" quote=”unsafe”]',
      'a=1 b="broken',
    ];
    for(const example of examples){
      const result=inspectGrammarFunnel(example);
      expect(result.selected).toBeNull();
      expect(result.disposition).not.toBe('candidate_only');
    }
  });

  it('has deterministic bounds and offsets across repeated identical events',()=>{
    const raw='tag=example sent="😄 \\"trusted\\"" bytes=42';
    const first=inspectGrammarFunnel(raw);
    expect(first).toEqual(inspectGrammarFunnel(raw));
    expect(first.selected?.sourceOracleVerified).toBe(false);
  });
});
