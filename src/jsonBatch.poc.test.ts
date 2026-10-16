import {describe,expect,it} from 'vitest';
import {parseJsonObjectBatch} from './jsonBatch';

const cloudTrail={
  Records:[
    {eventVersion:'1.08',eventTime:'2026-10-16T15:44:21Z',eventSource:'ec2.amazonaws.com',eventName:'StartInstances',sourceIPAddress:'192.0.2.10',awsRegion:'ap-northeast-2'},
    {eventVersion:'1.10',eventTime:'2026-10-16T15:44:22Z',eventSource:'signin.amazonaws.com',eventName:'ConsoleLogin',sourceIPAddress:'192.0.2.11',responseElements:{ConsoleLogin:'Success'}},
  ],
};

describe('JSON object-batch event breaker PoC',()=>{
  it('splits top-level object arrays without weakening the single-event JSON parser contract',()=>{
    const raw=JSON.stringify([
      {event:'alert',src:'192.0.2.1',dst:'198.51.100.1'},
      {event:'dns',src:'192.0.2.2',answers:['198.51.100.53','2001:db8::53']},
    ]);
    const parsed=parseJsonObjectBatch(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.batch.mode).toBe('top_level_array');
    expect(parsed.batch.records).toHaveLength(2);
    expect(parsed.batch.records[1]).toMatchObject({event:'dns',src:'192.0.2.2'});
  });

  it('splits CloudTrail-style Records wrappers while preserving wrapper metadata separately',()=>{
    const raw=JSON.stringify({...cloudTrail,source:'s3',region:'ap-northeast-2'});
    const parsed=parseJsonObjectBatch(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.batch.mode).toBe('records_wrapper');
    expect(parsed.batch.records).toEqual(cloudTrail.Records);
    expect(parsed.batch.container).toEqual({source:'s3',region:'ap-northeast-2'});
    console.log('JSON_BATCH_CLOUDTRAIL '+JSON.stringify({records:parsed.batch.records.length,mode:parsed.batch.mode}));
  });

  it('rejects scalar/mixed arrays, empty batches, unsafe keys, and malformed Records wrappers',()=>{
    const invalid=[
      '[]',
      '[1,2,3]',
      '[{"event":"a"},42]',
      '{"Records":[]}',
      '{"Records":[1,2]}',
      '{"Records":{"event":"a"}}',
      '{"Records":[{"constructor":"bad","event":"a"}]}',
      '[{"__proto__":{"polluted":true},"event":"a"}]',
      '{"items":[{"event":"a"}]}',
      '{"Records":[{"event":"a"}]',
    ];
    const accepted=invalid.filter(raw=>parseJsonObjectBatch(raw).ok);
    console.log('JSON_BATCH_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
