import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseApacheErrorLog} from './commonSecurityProfiles';

describe('external holdout residual grammar hardening',()=>{
  it('parses legacy and modern Apache error envelopes without tying to one message body',()=>{
    const samples=[
      '[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com',
      '[Fri Sep 09 10:42:29.902022 2011] [core:error] [pid 35708:tid 4328636416] [client 192.0.2.20:51514] AH00124: Request exceeded the limit of 10 internal redirects',
      '[Tue Oct 16 15:44:21 2026] [authz_core:notice] [pid 1200] Access policy evaluated',
    ];
    for(const raw of samples){
      const parsed=parseApacheErrorLog(raw);
      expect(parsed,raw).not.toBeNull();
      expect(extractGenericStructural(raw).errors,raw).toEqual([]);
    }
    expect(parseApacheErrorLog(samples[1])?.apache_error).toMatchObject({
      module:'core',level:'error',pid:'35708',tid:'4328636416',client_ip:'192.0.2.20',client_port:'51514',
    });
  });

  it('rejects impossible dates, invalid clients, unsafe level syntax, controls, and malformed brackets',()=>{
    const invalid=[
      '[Mon Feb 30 16:27:04 2015] [error] [client 10.17.42.3] bad date',
      '[Mon Aug 31 25:27:04 2015] [error] [client 10.17.42.3] bad clock',
      '[Mon Aug 31 16:27:04 2015] [core:error:extra] [client 10.17.42.3] bad level',
      '[Mon Aug 31 16:27:04 2015] [error] [client 999.0.0.1] bad client',
      '[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3:70000] bad port',
      '[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] bad\nnewline',
      '[Mon Aug 31 16:27:04 2015 [error] [client 10.17.42.3] bad bracket',
    ];
    expect(invalid.filter(raw=>parseApacheErrorLog(raw)!==null)).toEqual([]);
  });

  it('parses comma label:value Syslog bodies as a reusable dialect and rejects ambiguous shapes',()=>{
    const valid='<14>Jun 24 10:32:02 win-host WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123';
    const parsed=extractGenericStructural(valid);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.generic).toMatchObject({
      mode:'syslog_envelope_comma_label_value',
      fields:{'WinFileService Event':'read',Path:'/.DS_Store','File/Folder':'File',Size:'6.00 KB',User:'user@host',IP:'123.123.123.123'},
    });
    const invalid=[
      '<14>Jun 24 10:32:02 win-host app: Event: read, Path: only-two',
      '<14>Jun 24 10:32:02 win-host app: constructor: bad, Path: /tmp, Event: read',
      '<14>Jun 24 10:32:02 win-host app: Event: "unterminated, Path: /tmp, User: bob',
    ];
    const promoted=invalid.filter(raw=>{
      const parsed=extractGenericStructural(raw);
      const generic=parsed.fields.generic as {mode?:string}|undefined;
      return generic?.mode==='syslog_envelope_comma_label_value';
    });
    expect(promoted).toEqual([]);
  });
});
