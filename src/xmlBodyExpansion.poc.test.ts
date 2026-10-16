import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const eventXml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-16T15:44:21.1234567Z"/><Computer>WIN01</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="IpPort">51514</Data></EventData></Event>';

const wrapped=[
  eventXml,
  '<13>Oct 16 15:44:21 WIN01 winlog: '+eventXml,
  '<13>Oct 16 2026 15:44:21 WIN01 winlog: '+eventXml,
  '<13>2026-10-16T15:44:21Z WIN01 winlog: '+eventXml,
  '<13>1 2026-10-16T15:44:21Z WIN01 Microsoft-Windows-Security-Auditing 1268 EVT4625 - '+eventXml,
] as const;

describe('bounded XML security body PoC',()=>{
  it('extracts Windows Event XML standalone and behind common Syslog envelopes',()=>{
    const results=wrapped.map(raw=>extractGenericStructural(raw));
    const failures=results.map((result,index)=>({index,result})).filter(row=>row.result.errors.length);
    console.log('XML_SECURITY_BODY '+JSON.stringify({total:results.length,parsed:results.length-failures.length,failures:failures.map(row=>row.index)}));
    expect(failures).toEqual([]);
    for(const result of results){
      const xml=result.fields.xml as {root?:string;fields?:Record<string,unknown>}|undefined;
      expect(xml?.root).toBe('Event');
      expect(xml?.fields).toMatchObject({
        'Event.System.EventID':'4625',
        'Event.System.Computer':'WIN01',
        'Event.System.TimeCreated.@SystemTime':'2026-10-16T15:44:21.1234567Z',
        'Event.EventData.TargetUserName':'alice',
        'Event.EventData.IpAddress':'192.0.2.10',
      });
    }
  });

  it('rejects unsafe, malformed, entity-bearing, and too-shallow XML candidates',()=>{
    const invalid=[
      '<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event><A>&xxe;</A><B>2</B><C>3</C></Event>',
      '<Event><System><EventID>4625</EventID></System>',
      '<Event><EventData><Data Name="constructor">bad</Data><Data Name="A">1</Data><Data Name="B">2</Data></EventData></Event>',
      '<Event><A>1</A></Event>',
      '<Event><A>text<B>nested</B></A><C>3</C><D>4</D></Event>',
      '<?xml-stylesheet href="https://example.invalid/a.xsl"?><Event><A>1</A><B>2</B><C>3</C></Event>',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('XML_SECURITY_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
