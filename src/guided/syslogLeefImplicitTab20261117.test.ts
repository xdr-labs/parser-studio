import {describe,expect,it} from 'vitest';
import {readFileSync} from 'node:fs';
import {createDraft} from '../model';
import {extractGenericStructural} from '../genericStructural';
import {parseSyslogEnvelope} from '../syslogEnvelope';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {preview} from '../parser';

const raw=readFileSync('tests/fixtures/vendor-holdout-20261116/h_trendmicro_ds_leef/raw.log','utf8').replace(/\n+$/u,'');
const profile='leef2_implicit_tab' as const;
const rfc5424='<134>1 2026-11-16T10:15:04Z dsm01 trendmicro - 21 - '+
  'LEEF:2.0|Trend Micro|Deep Security Agent|20.0.1|21|name=Remote Domain Enforcement\tact=Deny\tsrc=203.0.113.77\tdst=10.1.10.9\tsrcPort=40022\tdstPort=22';

describe('Syslog-wrapped LEEF 2.0 implicit TAB profile',()=>{
  it('reads the vendor-grammar fixture behind RFC3164 with complete source coverage',()=>{
    const envelope=parseSyslogEnvelope(raw);
    expect(envelope?.message.startsWith('LEEF:2.0|')).toBe(true);
    const parsed=extractGenericStructural(raw,profile,'dedicated');
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.syslog).toMatchObject({variant:'rfc3164',hostname:'dsm01'});
    expect(parsed.fields.body).toMatchObject({leef_extension:{srcPort:'40022',dstPort:'22',act:'Deny'}});
    expect(parsed.fields.generic).toMatchObject({mode:'syslog_envelope_leef2_implicit_tab',source_raw:raw});
    expect(Object.keys((parsed.fields.body as Record<string,unknown>).leef_extension as object))
      .toEqual(['cat','name','desc','sev','cn1','cn1Label','dvchost','TrendMicroDsTenant','TrendMicroDsTenantId','act',
        'dstMAC','srcMAC','TrendMicroDsFrameType','src','dst','out','cs3','cs3Label','proto','srcPort','dstPort','cnt']);
    const automatic=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(automatic?.draft.genericStructuralProfile).toBe(profile);
    expect(automatic?.suite.counts).toMatchObject({total:1,matched:1,extracted:1,failures:0});
    expect(automatic?.suite.events[0]?.raw).toBe(raw);
    expect(automatic?.suite.events[0]?.parseStatus).toBe('FULL');
  });

  it('reads the same family behind RFC5424 and preserves UTF-8 and actual TAB separators',()=>{
    const unicode=rfc5424.replace('Remote Domain Enforcement','접근 허용 🔐');
    expect(unicode.includes('\\t')).toBe(false);
    const parsed=extractGenericStructural(unicode,profile,'dedicated');
    expect(parsed.errors).toEqual([]);
    expect(((parsed.fields.body as Record<string,unknown>).leef_extension as Record<string,unknown>).name).toBe('접근 허용 🔐');
    expect((parsed.fields.generic as Record<string,unknown>).source_raw).toBe(unicode);
    const result=preview(unicode,{...createDraft(),format:'generic_structural',genericStructuralProfile:profile,
      genericStructuralFamilyGrammar:'dedicated'});
    expect(result.counts).toMatchObject({total:1,matched:1,extracted:1,failures:0});
    expect(result.events[0]?.parseStatus).toBe('FULL');
  });

  it.each([
    ['incomplete key/value','<134>Nov 16 10:15:04 dsm01 LEEF:2.0|Acme|Agent|1|id|a=one\tb='],
    ['invalid CEF body','<134>Nov 16 10:15:04 dsm01 CEF:0|Acme|Agent|1|id|'],
    ['invalid LEEF body','<134>Nov 16 10:15:04 dsm01 LEEF:2.0|Acme|Agent|1|id|a=one\\tb=two'],
  ])('refuses %s without selecting a partial draft',(_name,source)=>{
    expect(extractGenericStructural(source,profile,'dedicated').errors).not.toEqual([]);
    expect(buildAutomaticGenericStructuralDraft(source,createDraft())).toBeNull();
  });

  it('keeps an explicit caret delimiter on the existing explicit-delimiter grammar',()=>{
    const source='<134>Nov 16 10:15:04 dsm01 LEEF:2.0|Acme|Agent|1|id|^|a=one^b=two';
    const parsed=extractGenericStructural(source,profile,'dedicated');
    expect(parsed.errors).toEqual([]);
    expect((parsed.fields.generic as Record<string,unknown>).mode).toBe('syslog_envelope_leef');
    expect((parsed.fields.body as Record<string,unknown>).a).toBe('one');
  });

  it('does not treat spaces as LEEF extension separators',()=>{
    const source='LEEF:2.0|Acme|Agent|1|id|first=one second=two\tthird=three';
    const parsed=extractGenericStructural(source,profile,'dedicated');
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.leef_extension).toEqual({first:'one second=two',third:'three'});
  });

  it('does not accept a malformed envelope as the new implicit-TAB profile',()=>{
    const source='<999>Nov 16 10:15:04 dsm01 '+raw.slice(raw.indexOf('LEEF:'));
    const parsed=extractGenericStructural(source,profile,'dedicated');
    expect(parsed.fields.generic).not.toMatchObject({mode:'syslog_envelope_leef2_implicit_tab'});
  });
});
