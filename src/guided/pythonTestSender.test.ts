import {describe,expect,it} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createDraft} from '../model';
import {preparePythonTestSender} from './pythonTestSender';

const original='{"timestamp":"2020-10-17T11:12:13Z","src_ip":"192.0.2.10","username":"alice","email":"alice@example.test","location":"Seoul"}';

describe('SCRIPT-1/2/3 browser-only Python standard library sender',()=>{
  it('embeds bounded exact Unicode events as base64 without an automatic target',()=>{
    const draft=createDraft();
    const src=original+'\n'+'action=deny src=192.0.2.22 user=kim';
    const generated=preparePythonTestSender(src,draft);
    expect(generated.filename).toBe('parser_studio_test_sender.py');
    expect(generated.eventCount).toBe(2);
    expect(generated.script).toContain('Sensor IP address');
    expect(generated.script).toContain('Type YES to start');
    expect(generated.script).toContain('INTERVAL_SECONDS = 1.0');
    expect(generated.script).toContain('DEFAULT_SEND_COUNT = 60');
    expect(generated.script).not.toContain('__PARSER_STUDIO_CONFIG_B64__');
    expect(generated.script).not.toContain(original);
    const encoded=generated.script.match(/CONFIG_B64 = "([^"]+)"/)?.[1];
    expect(encoded).toBeTruthy();
    const data=JSON.parse(new TextDecoder().decode(
      Uint8Array.from(atob(encoded!),v=>v.charCodeAt(0))));
    expect(data.events).toEqual([original,'action=deny src=192.0.2.22 user=kim']);
    expect(data.format).toBe('auto');
    expect(generated.warnings).toEqual(expect.arrayContaining([
      expect.stringContaining('NOT encryption'),
      expect.stringContaining('Unknown formats'),
    ]));
  });

  it('rejects oversized input, invalid CSV schema and unsupported framing',()=>{
    const draft=createDraft();
    expect(()=>preparePythonTestSender('',draft)).toThrow(/sample logs/);
    expect(()=>preparePythonTestSender('x'.repeat(65537),draft)).toThrow(/64 KiB/);
    draft.format='csv';
    draft.csvColumns='a,b,a';
    expect(()=>preparePythonTestSender('1,2,3',draft)).toThrow(/CSV column names/);
    draft.csvColumns='first,second,third';
    const output=preparePythonTestSender('1,2,3',draft);
    expect(output.eventCount).toBe(1);
    expect(output.script).toContain('import csv');
    draft.guided={...draft.guided!,eventBoundary:'unknown' as 'single-line'};
    expect(()=>preparePythonTestSender('1,2,3',draft)).toThrow(/event boundary/);
  });

  it('allows UTF-8 source without raw sample being uploaded or serialized into an API request',()=>{
    const draft=createDraft();
    const log='email="test@example.test" username="user😀" time=12:30:22';
    const prepared=preparePythonTestSender(log,draft);
    const encoded=prepared.script.match(/CONFIG_B64 = "([^"]+)"/)?.[1]||'';
    const config=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded),v=>v.charCodeAt(0))));
    expect(config.events).toEqual([log]);
    expect(prepared.eventCount).toBe(1);
    expect(prepared.script).not.toContain('http://');
    expect(prepared.script).not.toContain('https://');
  });

  it('refreshes the first key=value field when it directly follows a Syslog <PRI> (no space)',()=>{
    // Regression: a key immediately after <PRI> (for example FortiGate
    // "<190>date=... time=...") was not eligible, so date stayed stale while
    // time was refreshed, producing a self-inconsistent event.
    const lines=[
      '<190>date=2024-08-28 time=10:33:52 devname=\"FW1\" logid=\"0000000013\"',
      '<190> date=2024-08-28 time=10:33:52 devname=\"FW1\" logid=\"0000000013\"',
      '<134>user=alice action=allow',
    ];
    const generated=preparePythonTestSender(lines.join('\n'),createDraft());
    const dir=mkdtempSync(join(tmpdir(),'ps-sender-'));
    const file=join(dir,'sender.py');
    writeFileSync(file,generated.script);
    const code=[
      'import importlib.util,sys,json,datetime as dt',
      'spec=importlib.util.spec_from_file_location(\"s\",sys.argv[1])',
      'm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
      'cfg=m._payload()',
      'print(json.dumps({\"today\":dt.datetime.now().strftime(\"%Y-%m-%d\"),\"out\":[m.update_record(e,cfg) for e in cfg[\"events\"]]}))',
    ].join('\n');
    const result=JSON.parse(execFileSync('python3',['-c',code,file],{encoding:'utf8'}));
    const [attached,spaced,userLine]=result.out as string[];
    // PRI is preserved exactly and the first key is refreshed like the spaced form.
    expect(attached.startsWith('<190>date=')).toBe(true);
    expect(attached).toContain('date='+result.today+' ');
    expect(attached).not.toContain('date=2024-08-28');
    expect(spaced).toContain('date='+result.today+' ');
    expect(attached).toContain('devname=\"FW1\" logid=\"0000000013\"');
    expect(userLine.startsWith('<134>user=user')).toBe(true);
    expect(userLine).toMatch(/^<134>user=user\d{5} action=allow$/);
  });
});
