import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,it,expect} from 'vitest';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';
import {splitRfc6587OctetStreamBytes} from '../syslogFraming';
import {inspectOpaqueCountedRfc5424Source} from './standardOpaqueRfc5424MsgBytes';


type Claim={
  recordStartByte:number;recordEndByte:number;
  msgStartByte:number|null;msgEndByte:number|null;msgHex:string|null;
  encoding:'OPAQUE_MSG_ANY'|'MSG_UTF8_BOM'|'NO_MSG';
};
type Case={
  id:string;rawHex:string;sha256:string;accepted:boolean;claims:Claim[];
};
const frozen=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardOpaqueRfc5424MsgBytes.pinned.json'));
const digest='60f1234f32bf993aaeab1ff7d09168123cadd6edca63898f33adb3a2780cb902';
const sha=(raw:Uint8Array)=>createHash('sha256').update(raw).digest('hex');
if(sha(frozen)!==digest)throw Error('Opaque original source bytes oracle SHA mismatch');
const cases=(JSON.parse(frozen.toString('utf8')) as {cases:Case[]}).cases;

describe('RFC5424 MSG-ANY original arbitrary octets / RFC6587 count framing',()=>{
  it('pre-registers independent binary source byte evidence and denominators',()=>{
    expect(cases).toHaveLength(24);
    expect(cases.filter(x=>x.accepted)).toHaveLength(10);
    expect(cases.filter(x=>!x.accepted)).toHaveLength(14);
    expect(cases.flatMap(x=>x.claims)).toHaveLength(11);
  });
  it.each(cases.filter(x=>x.accepted))(
    'retains legal byte-level RFC5424 structured header with arbitrary MSG: $id',
    t=>{
      const wire=Buffer.from(t.rawHex,'hex');
      expect(sha(wire)).toBe(t.sha256);
      for(const expected of t.claims){
        const record=wire.subarray(expected.recordStartByte,expected.recordEndByte);
        const scanned=rfc5424SdByteEscapes(record);
        expect(scanned,t.id).not.toBeNull();
        if(!scanned)continue;
        const originalMsgStart=expected.msgStartByte===null?null:
          expected.msgStartByte-expected.recordStartByte;
        expect(scanned.messageStart).toBe(originalMsgStart);
        if(expected.msgHex===null)expect(scanned.messageStart).toBeNull();
        else expect(wire.subarray(
          expected.msgStartByte!,expected.msgEndByte!).toString('hex'))
          .toBe(expected.msgHex);
        expect(scanned.nativeTarget).toBe('NOT_VERIFIED');
        expect(scanned.canAutoPromote).toBe(false);
      }
    });
  it.each(cases)('keeps exact octet spans without interpreting wire MSG: $id',t=>{
    const wire=Buffer.from(t.rawHex,'hex');
    const frames=splitRfc6587OctetStreamBytes(wire);
    const inspected=inspectOpaqueCountedRfc5424Source(wire);
    expect(inspected.sourceSha256).toBe(t.sha256);
    expect(inspected.sourceBytes).toBe(wire.length);
    expect(inspected.canAutoPromote).toBe(false);
    expect(inspected.sourceComplete).toBe(false);
    expect(inspected.nativeVerified).toBe(false);
    expect(inspected.manufacturerVerified).toBe(false);
    expect(inspected.originalDeviceIdentity).toBe('NOT_ATTESTED');
    if(!t.accepted){
      expect(inspected.disposition).toBe('ABSTAIN_UNSAFE');
      expect(inspected.claims).toHaveLength(0);
      return;
    }
    expect(frames.ok).toBe(true);
    expect(inspected.disposition).toBe('REVIEW_ONLY_OPAQUE_MSG_BYTES');
    expect(inspected.claims).toHaveLength(t.claims.length);
    for(const [index,original] of t.claims.entries()){
      const claim=inspected.claims[index]!;
      expect({
        recordStartByte:claim.recordStartByte,
        recordEndByte:claim.recordEndByte,
        msgStartByte:claim.msgStartByte,
        msgEndByte:claim.msgEndByte,
        encoding:claim.encoding,
      }).toEqual({
        recordStartByte:original.recordStartByte,
        recordEndByte:original.recordEndByte,
        msgStartByte:original.msgStartByte,
        msgEndByte:original.msgEndByte,
        encoding:original.encoding,
      });
      if(original.msgHex!==null){
        expect(Buffer.from(wire.subarray(
          claim.msgStartByte!,claim.msgEndByte!)).toString('hex'))
          .toBe(original.msgHex);
      }else{
        expect(claim.msgStartByte).toBeNull();
        expect(claim.msgEndByte).toBeNull();
      }
    }
  });
});
