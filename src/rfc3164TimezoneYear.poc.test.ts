import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const body='action=block|src=192.0.2.10|dst=198.51.100.20|rule=deny-web';

const valid=[
  '<134>Oct 16 15:44:21 +0900 EDGE01 app: '+body,
  '<134>Oct 16 15:44:21 +09:00 EDGE01 app: '+body,
  '<134>Oct 16 2026 15:44:21 +0900 EDGE01 app: '+body,
  '<134>Oct 16 2026 15:44:21 +09:00 EDGE01 app: '+body,
  '<134>Oct 16 15:44:21 2026 +0900 EDGE01 app: '+body,
  '<134>Oct 16 15:44:21 2026 +09:00 EDGE01 app: '+body,
  '<134>Feb 29 2024 15:44:21 +0900 EDGE01 app: '+body,
  '<134>Feb 29 15:44:21 2024 +0900 EDGE01 app: '+body,
] as const;

const invalid=[
  '<134>Feb 29 2026 15:44:21 +0900 EDGE01 app: '+body,
  '<134>Feb 29 15:44:21 2026 +0900 EDGE01 app: '+body,
  '<134>Apr 31 2026 15:44:21 +0900 EDGE01 app: '+body,
  '<134>Apr 31 15:44:21 2026 +0900 EDGE01 app: '+body,
  '<134>Oct 16 15:44:21 +2500 EDGE01 app: '+body,
  '<134>Oct 16 2026 15:44:21 +2500 EDGE01 app: '+body,
] as const;

describe('RFC3164 timezone/year variant PoC',()=>{
  it('measures valid timezone-bearing BSD envelope coverage',()=>{
    const rows=valid.map(raw=>{
      const envelope=parseSyslogEnvelope(raw);
      const parsed=extractGenericStructural(raw);
      const generic=parsed.fields.generic as {mode?:string}|undefined;
      return {
        envelope:envelope!==null,
        structured:parsed.errors.length===0&&generic?.mode==='syslog_envelope_delimited_kv',
      };
    });
    const summary={
      total:rows.length,
      envelope:rows.filter(row=>row.envelope).length,
      structured:rows.filter(row=>row.structured).length,
    };
    console.log('RFC3164_TZ_VALID '+JSON.stringify(summary));
    expect(summary.total).toBe(valid.length);
  });

  it('rejects impossible year-aware dates and invalid zones',()=>{
    const accepted=invalid.filter(raw=>parseSyslogEnvelope(raw)!==null);
    const structured=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('RFC3164_TZ_INVALID '+JSON.stringify({
      total:invalid.length,envelopeAccepted:accepted.length,structuredAccepted:structured.length,
    }));
    expect(accepted).toEqual([]);
    expect(structured).toEqual([]);
  });
});
