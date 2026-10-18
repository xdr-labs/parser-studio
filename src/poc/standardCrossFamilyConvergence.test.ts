import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {extractFields} from '../parser';
import {extractStructuredFamily} from '../structuredFamilies';
import {parseZeekTsvBlock} from '../zeekTabular';
import {parseW3cLogBlock} from '../w3cTabular';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {unwrapSingleSyslogRecord} from '../syslogFraming';
import {inspectGrammarFunnel} from './grammarFunnel';

/**
 * STD-10/11 cross-surface conformance holds only: no manufacturer/native
 * golden, no confidence elevation from one syntactic grammar decision.
 */
describe('STD-10/11 isolated cross-format convergence and false-complete regressions',()=>{
  it('keeps byte-counted RFC6587 framing distinct from Syslog body interpretation',()=>{
    const wire='<34>1 2026-10-18T12:34:56Z h app 1 E - message=€😀';
    const octets=new TextEncoder().encode(wire).length;
    const good=unwrapSingleSyslogRecord(String(octets)+' '+wire);
    expect(good).toMatchObject({ok:true,mode:'rfc6587_octet_counting',message:wire,octets});
    const bad=unwrapSingleSyslogRecord(String(wire.length)+' '+wire);
    expect(bad.ok).toBe(false);
  });

  it('retains RFC5424 allowed repeated SD params and literal unknown escapes',()=>{
    const sd='[meta@32473 note="a\\qb" note="two"]';
    const wire='<34>1 2026-10-18T12:34:56Z edge app 1 E '+sd+' payload';
    const result=parseRfc5424Subset(wire);
    expect(result.ok).toBe(true);
    if(result.ok)expect(result.fields.syslog_structured_data).toBe(sd);
    expect(parseRfc5424Subset(
      '<34>1 2026-10-18T12:34:56Z edge app 1 E [x@32473 a="1"][x@32473 a="2"] body'
    ).ok).toBe(false);
  });

  it('uses shared generic CEF required-header and severity safeguards',()=>{
    const valid=extractStructuredFamily('CEF:0|Vendor|Endpoint|1|E1|Alert|5|act=deny','cef');
    expect(valid.errors).toEqual([]);
    expect(valid.fields.act).toBe('deny');
    for(const raw of [
      'CEF:0||Endpoint|1|E1|Alert|5|act=deny',
      'CEF:0|Vendor|Endpoint|1|E1|Alert|99|act=deny',
      'CEF:0|Vendor|Endpoint|1|E1|bad \\q|5|act=deny',
    ]){
      const bad=extractStructuredFamily(raw,'cef');
      expect(bad.errors.length).toBeGreaterThan(0);
      expect(bad.fields).toEqual({});
    }
  });

  it('uses LEEF 2.0 declared delimiter without guessing invalid control codes',()=>{
    const good=extractStructuredFamily(
      'LEEF:2.0|Vendor|Sensor|1|E1|0x5E|act=deny^severity=high','leef',
    );
    expect(good.errors).toEqual([]);
    expect(good.fields.act).toBe('deny');
    expect(good.fields.severity).toBe('high');
    const invalid=extractStructuredFamily(
      'LEEF:2.0|Vendor|Sensor|1|E1|0x00|act=deny','leef',
    );
    expect(invalid.errors.length).toBeGreaterThan(0);
  });

  it('refuses JSON loss with complete source rather than overwriting fields',()=>{
    const draft=createDraft();
    for(const raw of [
      '{"user":"alice","user":"bob"}',
      '{"event":{"user":"one","\\u0075ser":"two"}}',
      '{"count":9007199254740993}',
      '{"risk":1e999}',
      '{"surrogate":"\\uD800"}',
    ]){
      const parsed=extractFields(raw,'json',draft);
      expect(parsed.errors.length).toBeGreaterThan(0);
      expect(parsed.fields).toEqual({});
    }
    expect(extractFields('{"event":"allow","count":12}','json',draft).fields)
      .toMatchObject({event:'allow',count:12});
  });

  it('preserves RFC4180 unquoted field spaces and forbids liberal quote padding',()=>{
    const draft={...createDraft(),csvColumns:'action,message,status',
      csvDelimiter:',' as const};
    expect(extractFields(' allow, deny ,403','csv',draft)).toEqual({
      fields:{action:' allow',message:' deny ',status:'403'},errors:[],
    });
    const bad=extractFields('allow, "deny" ,403','csv',draft);
    expect(bad.errors.length).toBeGreaterThan(0);
    expect(bad.fields).toEqual({});
  });

  it('abstains on generic KV unconsumed source and unknown producer escaping',()=>{
    const draft=createDraft();
    const valid=extractFields('action=deny src=192.0.2.1','kv',draft);
    expect(valid.errors).toEqual([]);
    expect(valid.fields).toMatchObject({action:'deny',src:'192.0.2.1'});
    for(const raw of [
      'action=deny orphan_token',
      'msg="bad\\q" action=deny',
      'action=allow action=deny',
    ]){
      const observed=extractFields(raw,'kv',draft);
      expect(observed.errors.length).toBeGreaterThan(0);
      expect(observed.fields).toEqual({});
    }
  });

  it('rejects Zeek data after terminal close instead of claiming extra events',()=>{
    const original=[
      '#separator \\x09',
      '#fields\tts\tuid',
      '#types\ttime\tstring',
      '1.0\tC1',
      '#close\t2026-10-18-12-35-00',
    ].join('\n')+'\n';
    const pass=parseZeekTsvBlock(original);
    expect(pass.ok).toBe(true);
    if(pass.ok){
      expect(pass.block.closed).toBe(true);
      expect(pass.block.rowFieldSpans).toHaveLength(1);
    }
    const broken=parseZeekTsvBlock(original+'2.0\tC2\n');
    expect(broken.ok).toBe(false);
  });

  it('uses declared W3C field order and rejects malformed quoted source',()=>{
    const prefix='#Version: 1.0\n#Fields: time cs-method cs-uri\n';
    const good=parseW3cLogBlock(prefix+'12:34:56 GET "/first second"\n');
    expect(good.ok).toBe(true);
    if(good.ok){
      expect(good.block.rows).toHaveLength(1);
      expect(good.block.rows[0]?.['cs-uri']).toBe('/first second');
      expect(good.block.rowFieldSpans[0]).toHaveLength(3);
    }
    expect(parseW3cLogBlock(prefix+'12:34:56 GET "/bad"tail\n').ok).toBe(false);
  });

  it('does not infer KV producer schema when positional CSV also fits',()=>{
    const ambiguous=inspectGrammarFunnel('src=192.0.2.1,dst=198.51.100.2,act=deny');
    expect(ambiguous.disposition).toBe('ambiguous');
    expect(ambiguous.selected).toBeNull();
    for(const evidence of ambiguous.candidates)
      expect(evidence.sourceOracleVerified).toBe(false);
    const safe=inspectGrammarFunnel('src=192.0.2.1 dst=198.51.100.2 act=deny');
    expect(safe.disposition).toBe('candidate_only');
    expect(safe.selected?.sourceOracleVerified).toBe(false);
  });
});
