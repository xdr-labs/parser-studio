import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {validatePreviewRegexPattern} from '../regexSafety';
import {accountResidualRegions,accountResidualRegionsForSuite,isValueBearing,locateResidualRegions,
 regexCaptureSpans,utf8Offsets} from './residualProvenance';

// Final re-audit H-2: character-level provenance of previously unparsed regions. Each case below has a lossless
// recipe that must pass and lossy recipes that must be refused, on the same events.
function regexDraft(pattern:string,extra:Partial<ParserDraft>={}):ParserDraft{
 return {...createDraft(),format:'regex',pattern,preserveUnmapped:true,mappings:[],...extra} as ParserDraft;
}
function account(source:string,draft:ParserDraft,texts:string[][]){
 const lines=source.split('\n');
 const regions=texts.map((values,index)=>locateResidualRegions(lines[index]!,values)!);
 return accountResidualRegions(source,draft,regions);
}
const bytes=(text:string)=>new TextEncoder().encode(text).byteLength;
const KOREAN_USER='김민수';

const SQUID='1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html\n'+
 `1763859726.012      9 192.0.2.54 TCP_DENIED/407 3900 GET http://intranet.example.test/ ${KOREAN_USER} HIER_NONE/- text/html`;
const SQUID_RESIDUALS=[['1763859723.123    245 ',' TCP_MISS/200 5120 GET ',' - HIER_DIRECT/',' text/html'],
 ['1763859726.012      9 ',' TCP_DENIED/407 3900 GET ',` ${KOREAN_USER} HIER_NONE/- text/html`]];
const SQUID_PATTERN=String.raw`^(?<time>\d+\.\d{3}) +(?<elapsed>\d+) (?<client>[0-9.]+) (?<code>[A-Z_]+)/(?<status>\d{3}) (?<bytes>\d+) (?<method>[A-Z]+) (?<url>\S+) (?<user>\S+) (?<hierarchy>[A-Z_]+)/(?<peer>\S+) (?<type>\S+)$`;

describe('Squid access log (multi-token residual regions)',()=>{
 it('accounts for every residual character of a lossless recipe that splits regions into several fields',()=>{
  const result=account(SQUID,regexDraft(SQUID_PATTERN),SQUID_RESIDUALS);
  expect(result.events.map(event=>[event.method,event.required,event.missing])).toEqual([
   ['capture_spans',4,0],['capture_spans',3,0]]);
 });
 it('refuses a recipe that reads the HIER_ prefix as literal text (the value would lose it)',()=>{
  const result=account(SQUID,regexDraft(SQUID_PATTERN.replace(' (?<hierarchy>[A-Z_]+)/',' HIER_(?<hierarchy>[A-Z_]+)/')),SQUID_RESIDUALS);
  expect(result.events[0]).toMatchObject({method:'capture_spans',required:4,missing:1,reason:'UNACCOUNTED_SOURCE'});
  const raw=SQUID.split('\n')[0]!;const at=raw.indexOf('HIER_');
  expect(result.events[0]!.firstUnaccounted).toEqual({startByte:bytes(raw.slice(0,at)),endByte:bytes(raw.slice(0,at+5))});
 });
 it('refuses a recipe that reads the request method as literal text',()=>{
  const result=account(SQUID,regexDraft(SQUID_PATTERN.replace('(?<method>[A-Z]+)','GET')),SQUID_RESIDUALS);
  expect(result.events.map(event=>[event.missing,event.reason])).toEqual([[1,expect.any(String)],[0,'NOT_EVALUATED']]);
 });
 it('refuses a capture inside a repetition, which keeps only its last iteration',()=>{
  // The preview gate already refuses unbounded nested repetition; a bounded one passes it and reaches this check.
  const pattern=String.raw`^(?:(?<letter>[a-z]) ){3}(?<tail>\S+)$`;
  expect(validatePreviewRegexPattern(pattern)).toBeNull();
  const result=account('a b c tail',regexDraft(pattern),[['a b c tail']]);
  expect(result.events[0]).toMatchObject({method:'capture_spans',required:1,missing:1,reason:'REPEATED_CAPTURE'});
  expect(account(SQUID,regexDraft(String.raw`^(?:(?<token>\S+) +)+(?<type>\S+)$`),SQUID_RESIDUALS).events
   .map(event=>event.method)).toEqual(['unavailable','unavailable']);
 });
 it('tracks UTF-8 bytes: a non-ASCII user read as literal text is reported at its exact byte range',()=>{
  const raw=SQUID.split('\n')[1]!;
  const result=account(raw,regexDraft(SQUID_PATTERN.replace(' (?<user>\\S+) ',` ${KOREAN_USER} `)),[SQUID_RESIDUALS[1]!]);
  const at=raw.indexOf(KOREAN_USER);
  expect(result.events[0]).toMatchObject({missing:1,reason:'UNACCOUNTED_SOURCE',
   firstUnaccounted:{startByte:bytes(raw.slice(0,at)),endByte:bytes(raw.slice(0,at))+9}});
 });
 it('refuses a capture whose value does not reach the final output',()=>{
  const result=account(SQUID,regexDraft(SQUID_PATTERN,{preserveUnmapped:undefined}),SQUID_RESIDUALS);
  expect(result.events[0]).toMatchObject({missing:4,reason:'CAPTURE_NOT_IN_OUTPUT'});
 });
});

describe('Cisco ASA free text',()=>{
 const ASA='%ASA-6-302013: Built outbound TCP connection 123456 for outside:203.0.113.5/443 (203.0.113.5/443) to inside:192.168.1.5/51515 (198.51.100.7/51515)\n'+
  '%ASA-6-302014: Teardown TCP connection 123456 for outside:203.0.113.5/443 to inside:192.168.1.5/51515 duration 0:00:30 bytes 6123 TCP FINs';
 const whole=ASA.split('\n').map(line=>[line]);
 it('accepts a recipe that keeps the message text whole and reads its values in nested captures',()=>{
  const pattern=String.raw`^%(?<asa_code>(?<facility>[A-Z]+)-(?<severity>\d)-(?<message_id>\d+)): (?<message>(?<action>\w+) (?<detail>.+))$`;
  const result=account(ASA,regexDraft(pattern),whole);
  expect(result.events.map(event=>[event.method,event.missing])).toEqual([['capture_spans',0],['capture_spans',0]]);
 });
 it('refuses a recipe that splits the message code at its dashes without keeping the code whole',()=>{
  // A dash between a word and a digit may be a sign (`10:00:00-05:00`), so a recipe that reads it as pattern text
  // loses it unless an enclosing capture keeps the whole code (independent audit A-1).
  const pattern=String.raw`^%(?<facility>[A-Z]+)-(?<severity>\d)-(?<message_id>\d+): (?<message>(?<action>\w+) (?<detail>.+))$`;
  const result=account(ASA,regexDraft(pattern),whole);
  expect(result.events.map(event=>[event.missing,event.reason])).toEqual([[1,expect.any(String)],[0,'NOT_EVALUATED']]);
  expect(result.events[0]!.firstUnaccounted).toEqual({startByte:4,endByte:5});
 });
 it('refuses a recipe that reads the facility as literal pattern text',()=>{
  const pattern=String.raw`^%ASA-(?<severity>\d)-(?<message_id>\d+): (?<message>(?<action>\w+) (?<detail>.+))$`;
  const result=account(ASA,regexDraft(pattern),whole);
  expect(result.events.map(event=>[event.missing,event.reason])).toEqual([[1,expect.any(String)],[0,'NOT_EVALUATED']]);
  expect(result.events[0]!.firstUnaccounted).toEqual({startByte:1,endByte:5});
 });
 it('refuses a recipe that reads fixed message words outside every capture',()=>{
  const teardown=ASA.split('\n')[1]!;
  const pattern=String.raw`^%(?<asa_code>(?<facility>[A-Z]+)-(?<severity>\d)-(?<message_id>\d+)): (?<action>\w+) (?<protocol>[A-Z]+) connection (?<detail>.+)$`;
  const result=account(teardown,regexDraft(pattern),[[teardown]]);
  const at=teardown.indexOf('connection');
  expect(result.events[0]).toMatchObject({missing:1,firstUnaccounted:{startByte:at,endByte:at+10}});
 });
});

describe('Linux auditd records',()=>{
 const AUDIT='type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13\n'+
  'type=SYSCALL msg=audit(1364481364.001:24288): arch=c000003e syscall=59 success=yes exit=0';
 const whole=AUDIT.split('\n').map(line=>[line]);
 const LOSSLESS=String.raw`^type=(?<type>\S+) msg=(?<msg>audit\((?<audit_time>[0-9.]+):(?<audit_serial>\d+)\)): arch=(?<arch>\S+) syscall=(?<syscall>\d+) success=(?<success>\S+) exit=(?<exit>\S+)$`;
 it('accepts literal key names that precede a capture of the same name',()=>{
  const result=account(AUDIT,regexDraft(LOSSLESS),whole);
  expect(result.events.map(event=>[event.method,event.missing])).toEqual([['capture_spans',0],['capture_spans',0]]);
 });
 it('refuses a recipe that drops the sign of a negative exit code',()=>{
  const first=AUDIT.split('\n')[0]!;
  const result=account(first,regexDraft(LOSSLESS.replace('exit=(?<exit>\\S+)','(?<exit_key>exit)=-(?<exit>\\d+)')),[[first]]);
  const at=first.indexOf('-13');
  expect(result.events[0]).toMatchObject({method:'capture_spans',missing:1,firstUnaccounted:{startByte:at,endByte:at+1}});
 });
 it('refuses a key read as literal text before a capture of another name (the source field name is lost)',()=>{
  const result=account(AUDIT,regexDraft(LOSSLESS.replace('type=(?<type>','type=(?<event_type>')),whole);
  expect(result.events.map(event=>[event.method,event.missing])).toEqual([['capture_spans',1],['unavailable',0]]);
  expect(result.events[0]!.firstUnaccounted).toEqual({startByte:0,endByte:4});
 });
 it('refuses a fixed word read as literal text outside every capture',()=>{
  const pattern=LOSSLESS.replace('msg=(?<msg>audit\\((?<audit_time>','msg=audit\\((?<audit_time>').replace('(?<audit_serial>\\d+)\\)):','(?<audit_serial>\\d+)\\):');
  const result=account(AUDIT,regexDraft(pattern),whole);
  expect(result.events.map(event=>[event.method,event.missing])).toEqual([['capture_spans',1],['unavailable',0]]);
  expect(result.events[0]!.firstUnaccounted).toEqual({startByte:13,endByte:16});
 });
});

describe('literal digits and signs (verification D-1)',()=>{
 it('refuses IIS status digits read as literal pattern text',()=>{
  const source='2026-11-24 10:00:00 10.0.0.1 GET /index.html - 80 - 192.0.2.10 Mozilla/5.0 - 200 0 0 15';
  const pattern=String.raw`^(?<date>\S+) (?<time>\S+) (?<server>[0-9.]+) (?<method>[A-Z]+) (?<uri>\S+) - (?<port>\d+) - (?<client>[0-9.]+) (?<ua>\S+) - (?<status>\d+) 0 0 (?<taken>\d+)$`;
  const result=account(source,regexDraft(pattern),[[' Mozilla/5.0 - 200 0 0 15']]);
  expect(result.events[0]).toMatchObject({missing:1,reason:'UNACCOUNTED_SOURCE'});
  const lossless=pattern.replace(' 0 0 ',' (?<substatus>\\d+) (?<win32_status>\\d+) ');
  expect(account(source,regexDraft(lossless),[[' Mozilla/5.0 - 200 0 0 15']]).events[0]!.missing).toBe(0);
 });
 it('refuses an Apache time zone whose sign is read as literal text',()=>{
  const source='192.0.2.7 - alice [24/Nov/2026:10:00:00 -0500] "GET /a HTTP/1.1" 200 2326';
  const pattern=String.raw`^(?<client>[0-9.]+) - (?<user>\S+) \[(?<time>\S+) -(?<tz>\d{4})\] "(?<method>[A-Z]+) (?<path>\S+) (?<proto>\S+)" (?<status>\d+) (?<bytes>\d+)$`;
  const residual=[[' - alice [24/Nov/2026:10:00:00 -0500] "GET /a HTTP/1.1" 200 2326']];
  expect(account(source,regexDraft(pattern),residual).events[0]).toMatchObject({missing:1,
   firstUnaccounted:{startByte:source.indexOf('-0500'),endByte:source.indexOf('-0500')+1}});
  expect(account(source,regexDraft(pattern.replace(' -(?<tz>',' (?<tz>[-+]')),residual).events[0]!.missing).toBe(0);
 });
});

describe('independent audit of 240b2e6 (A-1 signs and separators, A-2 key names, A-3 capture identity)',()=>{
 it('A-1: refuses a recipe that drops the sign of an ISO time zone offset, accepts one that keeps it',()=>{
  const source='2026-11-25T10:00:00-05:00 user=alice action=login';
  const lossy=String.raw`^(?<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)-(?<tz>\d\d:\d\d) user=(?<user>\S+) action=(?<action>\S+)$`;
  expect(account(source,regexDraft(lossy),[[source]]).events[0]).toMatchObject({method:'capture_spans',missing:1,
   reason:'UNACCOUNTED_SOURCE',firstUnaccounted:{startByte:19,endByte:20}});
  const lossless=lossy.replace(')-(?<tz>\\d',')(?<tz>[-+]\\d');
  expect(account(source,regexDraft(lossless),[[source]]).events[0]).toMatchObject({method:'capture_spans',missing:0});
 });
 it('A-1: refuses decimal points, IPv6 colons and operators read as pattern text',()=>{
  // Only the value is residual: the fixed words around it were parsed before.
  const cases:[string,string,string,string][]=[
   ['ratio .5 ok',String.raw`^ratio \.(?<ratio>\d) (?<result>\S+)$`,'.','.5'],
   ['peer ::1 ok',String.raw`^peer ::(?<peer>\d) (?<result>\S+)$`,'::','::1'],
   ['zone GMT+9 ok',String.raw`^zone (?<zone>[A-Z]+)\+(?<offset>\d) (?<result>\S+)$`,'+','GMT+9'],
   ['check user!=root ok',String.raw`^check (?<field>[a-z]+)!=(?<value>\S+) (?<result>\S+)$`,'!=','user!=root'],
  ];
  for(const [source,pattern,lost,value] of cases){
   const at=source.indexOf(lost);
   expect(account(source,regexDraft(pattern),[[value]]).events[0],source).toMatchObject({missing:1,
    firstUnaccounted:{startByte:at,endByte:at+lost.length}});
  }
 });
 it('A-2: a non-ASCII key read as pattern text before a differently named capture is lost',()=>{
  const key='\uC0AC\uC6A9\uC790';
  const source=`${key}=kim action=login`;
  const pattern=String.raw`^`+key+String.raw`=(?<___>\S+) action=(?<action>\S+)$`;
  expect(account(source,regexDraft(pattern),[[source]]).events[0]).toMatchObject({missing:1,
   firstUnaccounted:{startByte:0,endByte:bytes(key)}});
 });
 it('A-2: a key with a dash is not exempt for a capture spelled with an underscore',()=>{
  const source='src-ip=192.0.2.1 action=allow';
  const pattern=String.raw`^src-ip=(?<src_ip>[0-9.]+) action=(?<action>\S+)$`;
  expect(account(source,regexDraft(pattern),[[source]]).events[0]!.missing).toBe(1);
 });
 it('A-3: a capture mapped twice cannot pay for a dropped capture with the same text',()=>{
  const source='tz -0500 offset -0500';
  const pattern=String.raw`^tz (?<tz>\S+) offset (?<offset>\S+)$`;
  const duplicated=regexDraft(pattern,{preserveUnmapped:undefined,mappings:[
   {id:'tz',source:'tz',target:'custom.tz',type:'string'},
   {id:'tz-again',source:'tz',target:'custom.offset',type:'string'}]});
  const event=preview(source,duplicated).events[0]!;
  expect(JSON.stringify(event.normalized).split('"-0500"').length-1).toBe(2);
  const values=[['-0500','-0500']];
  expect(account(source,duplicated,values).events[0]).toMatchObject({required:2,missing:1,reason:'CAPTURE_NOT_IN_OUTPUT',
   firstUnaccounted:{startByte:source.lastIndexOf('-0500'),endByte:source.length}});
  const both=regexDraft(pattern,{preserveUnmapped:undefined,mappings:[
   {id:'tz',source:'tz',target:'custom.tz',type:'string'},
   {id:'offset',source:'offset',target:'custom.offset',type:'string'}]});
  expect(account(source,both,values).events[0]!.missing).toBe(0);
 });
 it('A-3: a capture of fixed words that cannot be changed is decided by its field name',()=>{
  const source='proto TCP port 443';
  const pattern=String.raw`^proto (?<proto>TCP|UDP) port (?<port>\d+)$`;
  expect(account(source,regexDraft(pattern),[['TCP','443']]).events[0]).toMatchObject({required:2,missing:0});
 });
});

describe('independent re-audit of 4c04b0b (F-2 field identity, F-3 typed casts, F-4 signs and operators, F-5 keys)',()=>{
 const mapped=(pattern:string,mappings:{source:string;target:string;type:string}[],preserve=true)=>
  regexDraft(pattern,{preserveUnmapped:preserve?true:undefined,mappings:mappings.map((item,index)=>({id:'m'+index,...item}))} as Partial<ParserDraft>);
 it('F-2: a twin copy cannot pay for a capture whose cast rewrites its text',()=>{
  const source='sport=0443 dport=0443 user=alice';
  const pattern=String.raw`^sport=(?<sport>\d+) dport=(?<dport>\d+) user=(?<user>\S+)$`;
  const twin=mapped(pattern,[{source:'sport',target:'sport_text',type:'string'},{source:'sport',target:'sport_copy',type:'string'},
   {source:'dport',target:'dstport',type:'port'}]);
  const output=JSON.stringify(preview(source,twin).events[0]!.normalized);
  expect(output.split('"0443"').length-1).toBe(2);
  // The dport key is exempt only with a kept dport capture, so the refusal starts at the key.
  const at=source.indexOf('dport');
  expect(account(source,twin,[[source]]).events[0]).toMatchObject({missing:1,firstUnaccounted:{startByte:at,endByte:at+5}});
  const kept=mapped(pattern,[{source:'sport',target:'sport_text',type:'string'},{source:'dport',target:'dstport',type:'string'}]);
  expect(account(source,kept,[[source]]).events[0]!.missing).toBe(0);
 });
 it('F-2: a capture with a fixed suffix is probed where it can change',()=>{
  const source='host fw01.example.com peer fw01.example.com';
  const pattern=String.raw`^host (?<host>[a-z0-9]+\.example\.com) peer (?<peer>[a-z0-9]+\.example\.com)$`;
  const twice=mapped(pattern,[{source:'host',target:'host_a',type:'string'},{source:'host',target:'host_b',type:'string'}],false);
  expect(account(source,twice,[['fw01.example.com','fw01.example.com']]).events[0]).toMatchObject({required:2,missing:1});
  const both=mapped(pattern,[{source:'host',target:'host_a',type:'string'},{source:'peer',target:'host_b',type:'string'}],false);
  expect(account(source,both,[['fw01.example.com','fw01.example.com']]).events[0]!.missing).toBe(0);
 });
 it('F-3: lossless typed values whose changed text fails the cast are accepted',()=>{
  const cases:[string,string,{source:string;target:string;type:string}[]][]=[
   ['src=192.0.2.10 dst=255.255.255.255 proto=udp',String.raw`^src=(?<src>\S+) dst=(?<dst>\S+) proto=(?<proto>\S+)$`,
    [{source:'src',target:'srcip',type:'ip'},{source:'dst',target:'dstip',type:'ip'}]],
   ['user=alice admin=true',String.raw`^user=(?<user>\S+) admin=(?<admin>\S+)$`,[{source:'admin',target:'is_admin',type:'boolean'}]],
   ['dport=65535 user=bob',String.raw`^dport=(?<dport>\d+) user=(?<user>\S+)$`,[{source:'dport',target:'dstport',type:'port'}]],
  ];
  for(const [source,pattern,mappings] of cases)
   expect(account(source,mapped(pattern,mappings),[[source]]).events[0],source).toMatchObject({method:'capture_spans',missing:0});
 });
 it('F-4: a sign before a word, a plus and an operator are refused when read as pattern text',()=>{
  const cases:[string,string,string][]=[
   ['val -inf ok',String.raw`^val -(?<v>[a-z]+) (?<result>\S+)$`,'-'],
   ['lang C++ ok',String.raw`^lang (?<lang>[A-Z])\+\+ (?<result>\S+)$`,'++'],
   ['test x<=5 ok',String.raw`^test (?<field>[a-z])<=(?<limit>\d) (?<result>\S+)$`,'<='],
  ];
  for(const [source,pattern,lost] of cases){
   const value=source.split(' ')[1]!;const at=source.indexOf(lost);
   expect(account(source,regexDraft(pattern),[[value]]).events[0],source).toMatchObject({missing:1,
    firstUnaccounted:{startByte:at,endByte:at+lost.length}});
  }
 });
 it('F-5: a key before a quoted or bracketed value or with blanks around = keeps its exemption',()=>{
  const cases:[string,string][]=[
   ['devname="fw01" action=allow',String.raw`^devname="(?<devname>[^"]*)" action=(?<action>\S+)$`],
   ['user=[alice] action=allow',String.raw`^user=\[(?<user>[^\]]*)\] action=(?<action>\S+)$`],
   ['user = alice',String.raw`^user = (?<user>\S+)$`],
  ];
  for(const [source,pattern] of cases)
   expect(account(source,regexDraft(pattern),[[source]]).events[0],source).toMatchObject({method:'capture_spans',missing:0});
  expect(account('user="alice"',regexDraft(String.raw`^user="(?<name>[^"]*)"$`),[['user="alice"']]).events[0]!.missing).toBe(1);
 });
 it('F-7: events after the first unaccounted one are not evaluated',()=>{
  const source='login alice ok\nlogin bob ok\nlogin carol ok';
  const lossy=regexDraft(String.raw`^login (?<user>\S+) ok$`);
  const regions=source.split('\n').map(line=>locateResidualRegions(line,[line.slice(5)])!);
  expect(accountResidualRegions(source,lossy,regions).events.map(event=>[event.missing,event.reason])).toEqual([
   [1,'UNACCOUNTED_SOURCE'],[0,'NOT_EVALUATED'],[0,'NOT_EVALUATED']]);
 });
});

describe('verification of fbcb12f and a629389 (R-1 inconclusive probes, N-1 event profiles, N-2 quoted keys, R-2 flags)',()=>{
 const mapped=(pattern:string,mappings:{source:string;target:string;type:string}[],preserve=true,extra:Partial<ParserDraft>={})=>
  regexDraft(pattern,{preserveUnmapped:preserve?true:undefined,
   mappings:mappings.map((item,index)=>({id:'m'+index,...item})),...extra} as Partial<ParserDraft>);
 it('R-1: a capture of fixed alternatives whose cast rewrites it cannot be paid by a twin',()=>{
  const source='a 0443 b 0443';
  const pattern=String.raw`^(?<ka>a) (?<a>\d+) (?<kb>b) (?<b>0443|0080)$`;
  const twin=mapped(pattern,[{source:'a',target:'a1',type:'string'},{source:'a',target:'a2',type:'string'},
   {source:'b',target:'dstport',type:'port'}]);
  expect(account(source,twin,[[source]]).events[0]).toMatchObject({missing:1,firstUnaccounted:{startByte:9,endByte:13}});
  const kept=mapped(pattern,[{source:'a',target:'a1',type:'string'},{source:'b',target:'dstport',type:'string'}]);
  expect(account(source,kept,[[source]]).events[0]!.missing).toBe(0);
 });
 it('R-1: probes that only reach fixed text fall back to the field name, which a dropped twin does not have',()=>{
  const source='host web01.example.com peer web01.example.com';
  const pattern=String.raw`^host (?<host>web\d+\.example\.com) peer (?<peer>web\d+\.example\.com)$`;
  const texts=[['web01.example.com','web01.example.com']];
  const twice=mapped(pattern,[{source:'host',target:'host_a',type:'string'},{source:'host',target:'host_b',type:'string'}],false);
  expect(account(source,twice,texts).events[0]).toMatchObject({required:2,missing:1});
  const both=mapped(pattern,[{source:'host',target:'host_a',type:'string'},{source:'peer',target:'host_b',type:'string'}],false);
  expect(account(source,both,texts).events[0]!.missing).toBe(0);
 });
 it('N-1: with event profiles a capture that selects the profile cannot prove its value by a route change',()=>{
  const source='kind=0001 id=0001 user=alice';
  const pattern=String.raw`^kind=(?<kind>\d+) id=(?<id>\d+) user=(?<user>\S+)$`;
  const eventProfiles={discriminator:'kind',unknown:'reject',variants:[
   {name:'login',equals:'0001',mappings:[{id:'v1',source:'id',target:'id_text',type:'string'}]},
   {name:'logout',equals:'0009',mappings:[{id:'v3',source:'user',target:'logout_user',type:'string'}]}]};
  const draft=mapped(pattern,[{source:'kind',target:'kind_num',type:'integer'},{source:'id',target:'id_copy',type:'string'},
   {source:'user',target:'srcuser',type:'string'}],true,{eventProfiles} as unknown as Partial<ParserDraft>);
  const output=JSON.stringify(preview(source,draft).events[0]!.normalized);
  expect(output).toContain('"kind_num":1');
  expect(account(source,draft,[[source]]).events[0]).toMatchObject({missing:1,firstUnaccounted:{startByte:0,endByte:4}});
 });
 it('N-2: a key keeps its exemption when the capture starts at the opening quote',()=>{
  const source='devname="FG100E" action="deny" srcip=192.0.2.10';
  const pattern=String.raw`^devname=(?<devname>"[^"]*") action=(?<action>"[^"]*") srcip=(?<srcip>[0-9.]+)$`;
  expect(account(source,regexDraft(pattern),[[source]]).events[0]).toMatchObject({method:'capture_spans',missing:0});
 });
 it('R-2: a flag or sign after a quote, a bracket, a comma or = is refused when read as pattern text',()=>{
  const cases:[string,string,string][]=[
   ['val "-inf" ok',String.raw`^val "-(?<v>[a-z]+)" (?<result>\S+)$`,'"-inf"'],
   ['val (-inf) ok',String.raw`^val \(-(?<v>[a-z]+)\) (?<result>\S+)$`,'(-inf)'],
   ['opt --verbose ok',String.raw`^opt --(?<o>[a-z]+) (?<result>\S+)$`,'--verbose'],
  ];
  for(const [source,pattern,value] of cases){
   const at=source.indexOf('-');
   expect(account(source,regexDraft(pattern),[[value]]).events[0],source).toMatchObject({missing:1,
    firstUnaccounted:{startByte:at}});
  }
  expect(isValueBearing('src-ip',3)).toBe(false);
 });
});

describe('values that belong to the event',()=>{
 it('refuses an output that holds another event\'s value instead of this event\'s capture',()=>{
  const source='login alice ok\nlogin bob ok';
  const draft=regexDraft(String.raw`^login (?<user>\S+) (?<result>\S+)$`);
  const suite=preview(source,draft);
  const regions=[[{startByte:6,endByte:11}],[{startByte:6,endByte:9}]];
  expect(accountResidualRegionsForSuite(suite,draft,regions).events.map(event=>event.missing)).toEqual([0,0]);
  const tampered=structuredClone(suite);
  tampered.events[1]!.normalized=JSON.parse(JSON.stringify(tampered.events[1]!.normalized).replace('"bob"','"alice"'));
  expect(accountResidualRegionsForSuite(tampered,draft,regions).events[1]).toMatchObject({missing:1,reason:'CAPTURE_NOT_IN_OUTPUT'});
 });
 it('does not let a dropped capture borrow the identical output value of another capture',()=>{
  const draft=regexDraft(String.raw`^a (?<first>\d+) (?<second>\d+)$`);
  const suite=preview('a 200 200',draft);
  const tampered=structuredClone(suite);
  const normalized=JSON.stringify(tampered.events[0]!.normalized);
  expect(normalized.split('"200"').length-1).toBe(2);
  tampered.events[0]!.normalized=JSON.parse(normalized.replace(/,?"second":"200"/,''));
  expect(accountResidualRegionsForSuite(tampered,draft,[[{startByte:2,endByte:9}]]).events[0]!.missing).toBe(1);
 });
});

describe('evidence scope',()=>{
 it('reads a Syslog body expression at its offset in the event',()=>{
  const raw='<134>Nov 24 10:00:00 proxy1 squid[123]: 1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://x.test/ - HIER_DIRECT/198.51.100.10 text/html';
  const draft=regexDraft(SQUID_PATTERN,{format:'syslog_rfc3164',syslogBodyFormat:'regex'});
  const spans=regexCaptureSpans(raw,draft);
  expect('captures' in spans).toBe(true);
  const time=(spans as {captures:{name:string;startByte:number;endByte:number}[]}).captures.find(item=>item.name==='time')!;
  expect(raw.slice(time.startByte,time.endByte)).toBe('1763859723.123');
  expect(account(raw,draft,[[' TCP_MISS/200 5120 GET ']]).events[0]).toMatchObject({method:'capture_spans',missing:0});
 });
 it('reads a tagless RFC 3164 body expression, which has no raw-body reading (audit A-10)',()=>{
  const raw='<134>May 5 17:51:17 dev01 %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500';
  const body=raw.slice(raw.indexOf('%FTD'));
  const lossless=String.raw`^(?<raw>%FTD-\d-\d+: Built (?<direction>\w+) TCP connection (?<connection_id>\d+) for [^:]+:(?<src_ip>[0-9.]+)/(?<src_port>\d+))$`;
  const draft=regexDraft(lossless,{format:'syslog_rfc3164',syslogBodyFormat:'regex'});
  expect(account(raw,draft,[[body]]).events[0]).toMatchObject({method:'capture_spans',missing:0});
  const lossy=String.raw`^%FTD-\d-\d+: Built (?<direction>\w+) TCP connection (?<connection_id>\d+) for [^:]+:(?<src_ip>[0-9.]+)/(?<src_port>\d+)$`;
  expect(account(raw,regexDraft(lossy,{format:'syslog_rfc3164',syslogBodyFormat:'regex'}),[[body]]).events[0])
   .toMatchObject({method:'capture_spans',missing:1,firstUnaccounted:{startByte:raw.indexOf('FTD'),endByte:raw.indexOf('FTD')+'FTD-6-302013'.length}});
 });
 it('reports declarative grammars as unavailable so the strict whole-region rule stays',()=>{
  const draft={...createDraft(),format:'kv'} as ParserDraft;
  expect(accountResidualRegions('a=1 b=2',draft,[[{startByte:0,endByte:7}]]).events[0]).toMatchObject({method:'unavailable',reason:'NOT_REGEX'});
 });
 it('reports regions that do not fall on character boundaries as unavailable',()=>{
  const draft=regexDraft(String.raw`^(?<user>\S+)$`);
  expect(accountResidualRegions(KOREAN_USER,draft,[[{startByte:1,endByte:9}]]).events[0]).toMatchObject({method:'unavailable',reason:'INVALID_REGION'});
 });
 it('classifies signs, separators and null placeholders',()=>{
  const text='2026-11-24 -0500 +09 a=-5 x - y TCP_MISS/200 1.5 GMT+9 1e-5 -.5 ::1 user!=root index.html host:80 for x:y 50% ==';
  const bearing=(needle:string,offset=0)=>isValueBearing(text,text.indexOf(needle)+offset);
  // A dash between digits may be a sign (`10:00:00-05:00`): date parts are captured whole (audit A-1).
  expect(bearing('-11')).toBe(true);
  expect(bearing('-0500')).toBe(true);
  expect(bearing('+09')).toBe(true);
  expect(bearing('=-5',1)).toBe(true);
  expect(bearing('=-5')).toBe(false);
  expect(bearing(' - ',1)).toBe(false);
  expect(bearing('/200')).toBe(false);
  expect(bearing('_MISS')).toBe(true);
  expect(bearing('.5 ')).toBe(true);
  expect(bearing('+9 ')).toBe(true);
  expect(bearing('e-5',1)).toBe(true);
  expect(bearing('-.5')).toBe(true);
  expect(bearing('-.5',1)).toBe(true);
  expect(bearing('::1')).toBe(true);
  expect(bearing('::1',1)).toBe(true);
  expect(bearing('!=')).toBe(true);
  // An `=` inside an operator is part of it (re-audit F-4/F-8): `!=`, `<=`, `>=`.
  expect(bearing('!=',1)).toBe(true);
  expect(bearing('.html')).toBe(false);
  expect(bearing(':80')).toBe(false);
  expect(bearing(':y')).toBe(false);
  expect(bearing('% ')).toBe(true);
  expect(bearing('==')).toBe(true);
  expect(utf8Offsets('a김b')).toEqual([0,1,4,5]);
 });
});
