import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {SYSLOG_POC_NEGATIVE,SYSLOG_POC_POSITIVE} from './syslogPocCorpus';

function envelopeParsed(fields:Record<string,unknown>):boolean{
  return !!fields.syslog||!!fields.watchguard_header;
}

function structuredBodyParsed(fields:Record<string,unknown>):boolean{
  if(fields.asa||fields.watchguard||fields.juniper||fields.body)return true;
  const generic=fields.generic;
  if(!generic||typeof generic!=='object'||Array.isArray(generic))return false;
  const mode=(generic as {mode?:unknown}).mode;
  return typeof mode==='string'&&[
    'space_kv','delimited_kv','rfc3164_positional_csv','prefixed_json',
  ].includes(mode);
}

describe('syslog foundation PoC baseline',()=>{
  it('records the current engine coverage without changing acceptance behavior',()=>{
    const positive=SYSLOG_POC_POSITIVE.map(sample=>{
      const parsed=extractGenericStructural(sample.raw);
      return {
        id:sample.id,
        ok:parsed.errors.length===0,
        envelope:envelopeParsed(parsed.fields),
        structured:structuredBodyParsed(parsed.fields),
      };
    });
    const negatives=SYSLOG_POC_NEGATIVE.map(raw=>({
      raw,
      accepted:extractGenericStructural(raw).errors.length===0,
    }));
    const summary={
      positives:positive.length,
      parsed:positive.filter(item=>item.ok).length,
      envelope:positive.filter(item=>item.envelope).length,
      structuredBody:positive.filter(item=>item.structured).length,
      failures:positive.filter(item=>!item.ok).map(item=>item.id),
      negativeAccepted:negatives.filter(item=>item.accepted).length,
      negativeAcceptedSamples:negatives.filter(item=>item.accepted).map(item=>item.raw),
    };
    console.log('SYSLOG_POC_BASELINE '+JSON.stringify(summary));
    expect(positive.length).toBeGreaterThan(40);
  });
});
