/**
 * The readable events of a sample are split on the verdicts that let the Auto Parser go on (2026-11-25).
 *
 * The Auto Parser goes on with a sample only when the server analysis read every event (SOURCE_PARSED) and the
 * first scan recognized every event. The offer "Create the parser for the readable events" used the browser
 * preview verdict alone, so it could keep an event the journey then refused: the sample of readable events
 * stopped again with no way forward. An RFC 5424 line with VERSION 2 was shown as read completely, against the
 * owner decision of 2026-11-13 (only VERSION 1 is read). SYNTHETIC lines.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {readableEvents} from './readableEvents';

const V=(version:number,n:number)=>'<165>'+version+' 2026-11-13T10:00:0'+n+'Z edge fw 12'+n+' ID'+n+' - srcip=10.1.1.'+n+
  ' dstip=203.0.113.'+n+' srcport=100'+n+' dstport=443 action=allow';
const SSHD='<38>Nov 13 10:00:00 host1 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2';
const FREE='kernel panic - not syncing: fatal exception in interrupt';
const KV=(n:number)=>'<134>Nov 13 10:00:0'+n+' host2 myfw: srcip=10.1.1.'+n+' dstip=203.0.113.9 srcport=100'+n+' dstport=443 action=allow';

function split(lines:readonly string[],sourceParsed?:readonly boolean[]){
  const sample=lines.join('\n');
  const suite=preview(sample,{...createDraft(),format:'auto'});
  return readableEvents(sample,suite,analyzeLogEnvelopes(sample,'single-line').events,sourceParsed);
}

describe('the browser preview does not read an RFC 5424 version other than 1',()=>{
  it.each([0,2,9])('VERSION %i is not read completely',version=>{
    const suite=preview(V(version,1),{...createDraft(),format:'auto'});
    expect(suite.events[0]!.parseStatus).not.toBe('FULL');
  });
  it('VERSION 1 is read completely',()=>{
    expect(preview(V(1,1),{...createDraft(),format:'auto'}).events[0]!.parseStatus).toBe('FULL');
  });
});

describe('the readable events are the events the Auto Parser can go on with',()=>{
  it('leave out an event the first scan did not recognize, whatever the browser preview says',()=>{
    // The browser preview keeps the whole sshd message as text and calls the event FULL; the first scan does not
    // recognize a body, so the Auto Parser asks for a rule and would not go on with it.
    const found=split([SSHD,KV(1),KV(2)],[true,true,true]);
    expect(found).not.toBeNull();
    expect(found!.source).toBe([KV(1),KV(2)].join('\n'));
    expect(found!.excluded.flatMap(group=>group.events)).toEqual([1]);
  });

  it('leave out an event the server analysis did not read completely',()=>{
    const found=split([KV(1),KV(2),KV(3)],[true,false,true]);
    expect(found!.source).toBe([KV(1),KV(3)].join('\n'));
    expect([found!.count,found!.total]).toEqual([2,3]);
    expect(found!.excluded.flatMap(group=>group.events)).toEqual([2]);
  });

  it('keep only the VERSION 1 event of RFC 5424 lines with VERSION 1, 2 and 12',()=>{
    const found=split([V(1,1),V(2,2),V(12,3)],[true,false,false]);
    expect(found!.source).toBe(V(1,1));
    expect(found!.excluded.flatMap(group=>group.events).sort()).toEqual([2,3]);
  });

  it('are not offered when the server analysis does not describe the sample event by event',()=>{
    expect(split([KV(1),FREE])).not.toBeNull();
    expect(split([KV(1),FREE],[true])).toBeNull();
    expect(split([KV(1),FREE],[])).toBeNull();
  });

  it('are nothing to split when the analysis accepts no event',()=>{
    expect(split([KV(1),FREE],[false,false])).toBeNull();
  });
});
