import {describe,it,expect} from 'vitest';
import {inspectMarkedBoundaries,markBoundarySelection} from './manualSourceBoundaries';

describe('Explicit literal forwarder prefix/postfix marks',()=>{
  const source='relay: {"message":"로그인 실패","src":"198.51.100.1"} [end]\n'+
    'relay: {"message":"認証失敗","src":"198.51.100.2"} [end]';
  it('marks exactly the first record edges, never an incidental substring',()=>{
    expect(markBoundarySelection(source,0,7,'prefix')).toEqual({ok:true,value:'relay: '});
    const end=source.indexOf('\n');
    expect(markBoundarySelection(source,end-6,end,'suffix')).toEqual({ok:true,value:' [end]'});
    expect(markBoundarySelection(source,1,7,'prefix')).toMatchObject({ok:false});
    expect(markBoundarySelection(source,end-6,end-1,'suffix')).toMatchObject({ok:false});
    expect(markBoundarySelection(source,end+1,end+4,'prefix')).toMatchObject({ok:false});
  });
  it('preserves original multilingual source and exact UTF-8 payload byte ranges',()=>{
    const result=inspectMarkedBoundaries(source,{prefix:'relay: ',suffix:' [end]'});
    expect(result).toMatchObject({status:'READY',total:2,matched:2,unmatched:0,
      nativeVerified:false,targetVerified:false});
    const encoded=new TextEncoder().encode(source);
    const decoder=new TextDecoder('utf-8',{fatal:true});
    for(const event of result.events){
      expect(event.original).toContain('relay: ');
      expect(decoder.decode(encoded.slice(event.payloadStartByte,event.payloadEndByte)))
        .toBe(event.body);
      expect(decoder.decode(encoded.slice(event.sourceStartByte,event.sourceEndByte)))
        .toBe(event.original);
      expect(event.body).not.toContain(' [end]');
    }
    expect(result.events.map(e=>JSON.parse(e.body).message)).toEqual(['로그인 실패','認証失敗']);
  });
  it('keeps mismatched original records rather than discarding them',()=>{
    const sample='relay: action=allow [end]\nother: action=deny [end]';
    const r=inspectMarkedBoundaries(sample,{prefix:'relay: ',suffix:' [end]'});
    expect(r).toMatchObject({status:'PARTIAL',matched:1,unmatched:1,total:2});
    expect(r.events[1]!.body).toBe('other: action=deny [end]');
    expect(r.events[1]!.status).toBe('UNMATCHED');
  });
  it('never claims a usable format without explicit marks and bounded input',()=>{
    expect(inspectMarkedBoundaries(source,{prefix:'',suffix:''}).status).toBe('NO_MARKERS');
    expect(inspectMarkedBoundaries(source,{prefix:'relay:\n',suffix:''}).status).toBe('UNSAFE');
    expect(inspectMarkedBoundaries('a'.repeat(65_537),{prefix:'a',suffix:''}).status).toBe('UNSAFE');
    expect(inspectMarkedBoundaries('a\n'.repeat(501),{prefix:'a',suffix:''}).status).toBe('UNSAFE');
    expect(inspectMarkedBoundaries('relay: ',{prefix:'relay: ',suffix:''}).status).toBe('PARTIAL');
  });
  it('does not confuse UTF-16 selections and UTF-8 source offsets',()=>{
    const content='한글> {"action":"deny"}\n한글> {"action":"allow"}';
    const m=markBoundarySelection(content,0,'한글> '.length,'prefix');
    expect(m).toEqual({ok:true,value:'한글> '});
    const r=inspectMarkedBoundaries(content,{prefix:'한글> ',suffix:''});
    expect(r.status).toBe('READY');
    expect(r.events[0]!.payloadStartByte).toBe(new TextEncoder().encode('한글> ').length);
  });
});
