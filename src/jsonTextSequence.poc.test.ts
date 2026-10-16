import {describe,expect,it} from 'vitest';
import {parseJsonTextSequence} from './jsonTextSequence';

const RS='\u001e';

describe('RFC7464 JSON text sequence security-event PoC',()=>{
  it('parses object records including pretty/multiline JSON using RS framing',()=>{
    const one=JSON.stringify({event:'alert',src:'192.0.2.1',nested:{severity:8}});
    const two=JSON.stringify({event:'login',user:'alice',details:{ip:'192.0.2.2',success:true}},null,2);
    const raw=RS+one+'\n'+RS+two+'\n';
    const parsed=parseJsonTextSequence(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.sequence.records).toHaveLength(2);
    expect(parsed.sequence.records[0]).toMatchObject({event:'alert',src:'192.0.2.1'});
    expect(parsed.sequence.records[1]).toMatchObject({event:'login',user:'alice',details:{success:true}});
    expect(parsed.sequence.rawJsonTexts).toEqual([one,two]);
    console.log('JSON_SEQ '+JSON.stringify({records:parsed.sequence.records.length,multiline:two.includes('\n')}));
  });

  it('preserves escaped record-separator and newline characters inside strings',()=>{
    const value={event:'message',text:'line1\nline2\u001einside'};
    const parsed=parseJsonTextSequence(RS+JSON.stringify(value)+'\n');
    expect(parsed.ok).toBe(true);
    if(parsed.ok)expect(parsed.sequence.records[0]).toEqual(value);
  });

  it('rejects missing framing LF, scalar/array records, malformed JSON, unsafe keys, and empty frames',()=>{
    const invalid=[
      JSON.stringify({event:'no-rs'})+'\n',
      RS+JSON.stringify({event:'no-lf'}),
      RS+'[1,2,3]\n',
      RS+'42\n',
      RS+'null\n',
      RS+'{"event":"broken"\n',
      RS+'{"constructor":"bad","event":"a"}\n',
      RS+'{"event":"a"}\n'+RS+'\n',
      RS+'{"event":"a"}\n'+RS+'{"event":"b"}',
    ];
    const accepted=invalid.filter(raw=>parseJsonTextSequence(raw).ok);
    console.log('JSON_SEQ_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
