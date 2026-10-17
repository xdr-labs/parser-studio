import {describe,expect,it} from 'vitest';
import {inspectGrammarFunnel,replayCandidate} from './grammarFunnel';
import {scanDelimitedRow,scanKeyValues,scanPrefixedKeyValues} from './losslessLexer';

describe('shared lossless lexer bounded fail-closed security controls',()=>{
  it('rejects 288 distinct malformed KV mutations without dropping fields',()=>{
    const malformed:string[]=[];
    for(let i=0;i<32;i++){
      malformed.push(
        `key${i}=1 key${i}=2`,
        `source-${i}=x source_${i}=y`,
        `key${i}=1 constructor=bad`,
        `key${i}=1 extra="unterminated`,
        `key${i}=1 extra="quoted"tail`,
        `key${i}=1 extra=2 trailing`,
        `key${i}=1 extra=2\n`,
        `key${i}=1 extra=2\0`,
        `key${i}=1 extra=2\u201c`,
      );
    }
    expect(malformed.length).toBe(288);
    expect(malformed.every(raw=>scanKeyValues(raw,0,'space')===null)).toBe(true);
    expect(malformed.filter(raw=>inspectGrammarFunnel(raw).disposition==='candidate_only'))
      .toEqual([]);
  });

  it('retains duplicate source key values as ordered evidence, never a verified map',()=>{
    const input='message="first" message="second" message="third" action=allow';
    const result=scanKeyValues(input,0,'space',{preserveRepeated:true});
    expect(result?.fields.map(f=>f.value)).toEqual(['first','second','third','allow']);
    expect(result?.repeatedKeys).toEqual(['message','message']);
    expect(replayCandidate(result!)).toMatchObject({
      repeatedSourceKeys:2,sourceOracleVerified:false,fullBodyCovered:false,
    });
    expect(inspectGrammarFunnel(input)).toMatchObject({
      disposition:'partial_candidate',selected:{repeatedSourceKeys:2},
    });
  });

  it('rejects boundary, field-count and unpaired-surrogate abuse',()=>{
    expect(scanKeyValues('a=1 b=2'.repeat(4000),0,'space')).toBeNull();
    expect(scanKeyValues('a=1 b=2\uDC00',0,'space')).toBeNull();
    expect(scanPrefixedKeyValues('198.51.100.1 id=a\nname=b',0)).toBeNull();
    const oversized=new Array(257).fill(0).map((_,i)=>`field_${i}=${i}`).join(' ');
    expect(scanKeyValues(oversized,0,'space',{preserveRepeated:true})).toBeNull();
  });

  it('rejects four malformed RFC4180 quoting structures rather than shifting columns',()=>{
    const invalid=[
      'one,two,"unfinished',
      'one,two,"closed"tail,three',
      'one,two,bad"quote,three',
      'one,two,smart\u201dquote',
    ];
    expect(invalid.map(raw=>scanDelimitedRow(raw,0,'comma'))).toEqual([
      null,null,null,null,
    ]);
  });

  it('never certifies an invalid vendor-owned Syslog timestamp from KV-looking bodies',()=>{
    const bodies=['src=1 dst=2 reason=malformed','date=2026-10-17 time=08:00:00 x=3'];
    for(const body of bodies){
      const raw='<85>1 2023-01-13T10:10:16--5:00 fw CP-GW - - - '+body;
      const result=inspectGrammarFunnel(raw);
      expect(result.selected).toBeNull();
      expect(result.disposition).toBe('invalid_envelope');
    }
  });
});
