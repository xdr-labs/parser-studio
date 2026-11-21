import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from '../genericStructural';
import {createDraft} from '../model';
import {lookupFieldValue} from '../fieldPaths';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

// Issue #315: a source key that is also the name of an Object.prototype member
// is ordinary log data. It must behave exactly like any other key.
const PROTOTYPE_MEMBER_KEYS=['toString','valueOf','hasOwnProperty','isPrototypeOf','toLocaleString','propertyIsEnumerable'];
const CONTROL='normalKey';

// One sample per Generic Structural key=value grammar; K is the key under test.
const SHAPES:Record<string,(key:string)=>string>={
  'tagged BSD Syslog comma KV':key=>
    '<134>Nov 16 10:15:04 web01 portal: '+key+'="x",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok",user="bob"',
  'comma KV tail after a positional prefix':key=>
    '<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, '+key+'=one',
  'repeated comma KV tail key':key=>
    '<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, '+key+'=one, '+key+'=two',
  'bracket colon KV':key=>
    '<134>1 2020-03-30T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"; '+key+':"ops"; '+key+':"admins"; note:"x;y"]',
  'PRI-prefixed space KV':key=>
    '<134>date=2023-02-23 time=22:49:29 tz="+0500" devname=FMG-VM device_id=FMG001 type=event '+key+'=information desc="User login successful" status=success',
  'prefix plus space KV':key=>
    '2023:04:28-00:50:54 sophos-test-vm1 ulogd[12511]: id="2021" severity="info" '+key+'="SecureNet" sub="packetfilter" action="drop"',
  'sentence-prefixed comma KV':key=>
    "Info: Response received for file reputation query from Cloud. FileName = 'mod-6.exe', MID = 5, "+key+' = MALICIOUS, Malware = W32.TEST, upload_action = 2',
};

function functionPaths(value:unknown,path='$',found:string[]=[]):string[]{
  if(typeof value==='function')found.push(path);
  else if(value&&typeof value==='object')
    for(const key of Reflect.ownKeys(value))functionPaths((value as Record<PropertyKey,unknown>)[key],path+'.'+String(key),found);
  return found;
}

describe('Issue #315 prototype-member source keys are ordinary data',()=>{
  for(const [shape,sample] of Object.entries(SHAPES)){
    const control=extractGenericStructural(sample(CONTROL));
    it(shape+': the control sample is extracted',()=>{
      expect(control.errors).toEqual([]);
      expect(JSON.stringify(control.fields)).toContain('"'+CONTROL+'"');
    });
    for(const key of PROTOTYPE_MEMBER_KEYS){
      it(shape+': '+key+' is extracted exactly like an ordinary key',()=>{
        const result=extractGenericStructural(sample(key));
        expect(result.errors).toEqual([]);
        expect(functionPaths(result.fields)).toEqual([]);
        // Same structure, same values, same repeated-value arrays as the control; only the key name differs.
        expect(JSON.stringify(result.fields).split(key).join(CONTROL)).toBe(JSON.stringify(control.fields));
        expect(()=>structuredClone(result.fields)).not.toThrow();
      });
    }
  }

  for(const key of PROTOTYPE_MEMBER_KEYS){
    it('Auto Parser adopts two tagged Syslog KV events whose field is named '+key,()=>{
      const source=[
        '<134>Nov 16 10:15:04 web01 portal: '+key+'="x",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok",user="bob"',
        '<134>Nov 16 10:15:05 web01 portal: '+key+'="y",src="203.0.113.6",dst="10.1.1.9",port="443",result="ok",user="eve"',
      ].join('\n');
      const adopted=buildAutomaticGenericStructuralDraft(source,createDraft());
      expect(adopted).not.toBeNull();
      const {suite,draft}=adopted!;
      expect(suite.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
      const path='generic.fields.'+key;
      expect(draft.mappings.filter(mapping=>mapping.source===path)).toHaveLength(1);
      suite.events.forEach((event,index)=>{
        expect(event.parseStatus).toBe('FULL');
        expect(functionPaths({fields:event.fields,normalized:event.normalized})).toEqual([]);
        expect(lookupFieldValue(event.fields,path)).toEqual({found:true,value:index===0?'x':'y'});
        expect(lookupFieldValue(event.normalized,'parserstudio_source.'+path)).toEqual({found:true,value:index===0?'x':'y'});
        // A neighbouring field keeps its own value: no cross-field or cross-event mixing.
        expect(lookupFieldValue(event.fields,'generic.fields.src')).toEqual({found:true,value:index===0?'203.0.113.5':'203.0.113.6'});
      });
      // The source key reaches the output under its own, unchanged name.
      const mapping=draft.mappings.find(item=>item.source===path)!;
      expect(mapping.target).toBe(key);
      expect(JSON.stringify(suite.events[0]!.normalized)).toContain('"'+key+'":"x"');
    });

    it('a field named '+key+' that is absent from one event is not read from the prototype',()=>{
      const source=[
        '<134>Nov 16 10:15:04 web01 portal: '+key+'="x",src="203.0.113.5",dst="10.1.1.9",port="443"',
        '<134>Nov 16 10:15:05 web01 portal: other="y",src="203.0.113.6",dst="10.1.1.9",port="443"',
      ].join('\n');
      const adopted=buildAutomaticGenericStructuralDraft(source,createDraft());
      expect(adopted).not.toBeNull();
      const second=adopted!.suite.events[1]!;
      expect(lookupFieldValue(second.fields,'generic.fields.'+key)).toEqual({found:false});
      expect(functionPaths(second.normalized)).toEqual([]);
      expect(JSON.stringify(second.normalized)).not.toContain('"'+key+'"');
    });
  }
});
