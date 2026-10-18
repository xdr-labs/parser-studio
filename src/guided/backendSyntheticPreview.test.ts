import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import type { BackendCapabilities } from './backendCapabilities';
import { requestAuthorizedSyntheticPreview, validateBackendSyntheticPreviewCapability } from './backendSyntheticPreview';

const caps = {
  testLab:{
    offlineJsonPreview:true,
    requiresBackendPreviewAuthorization:true,
    liveSensorSenderEnabled:false,
    sensorIngestVerified:false,
    runtimeParsingVerified:false,
  },
} as unknown as BackendCapabilities;
const response={
  contract:'parser-studio.synthetic-preview.v0.1',
  format:'json',
  syntheticEvent:JSON.stringify({
    time:'2026-10-12T02:00:00Z',
    src_ip:'192.0.2.42',username:'synthetic_user_100123',
    url:'https://synthetic.invalid/synthetic/1234abcd',
    action:'allow',
  }),
  generatedAt:'2026-10-12T02:00:00.000Z',
  sequence:0,
  changedPaths:['time','src_ip','username','url'],
  safeToSendToSensor:false,runtimeParsingVerified:false,targetSensorVerified:false,
};
const fake=(body:unknown,status=200)=>vi.fn(async()=>({
  status,json:async()=>body,
})) as unknown as typeof fetch;

describe('authorized synthetic-only backend preview, no customer logs or sensor send',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('requires server-side auth flag, JSON preview support and false runtime/sensor status',()=>{
    expect(()=>validateBackendSyntheticPreviewCapability(caps)).not.toThrow();
    for(const testLab of [
      undefined,
      {...caps.testLab,offlineJsonPreview:false},
      {...caps.testLab,requiresBackendPreviewAuthorization:false},
      {...caps.testLab,liveSensorSenderEnabled:true},
      {...caps.testLab,sensorIngestVerified:true},
      {...caps.testLab,runtimeParsingVerified:true},
    ]) expect(()=>validateBackendSyntheticPreviewCapability({testLab} as BackendCapabilities)).toThrow();
  });
  it('requires a user click; request includes only publicly synthetic static values, never logs or credentials',async()=>{
    const request=fake(response);
    const result=await requestAuthorizedSyntheticPreview(caps,request);
    expect(result).toMatchObject({
      format:'json',safeToSendToSensor:false,generatedAt:'2026-10-12T02:00:00.000Z',
      runtimeParsingVerified:false,targetSensorVerified:false,
      changedPaths:['time','src_ip','username','url'],
    });
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/preview');
    expect(init).toMatchObject({method:'POST',credentials:'same-origin',cache:'no-store'});
    const body=JSON.parse(init.body);
    expect(body).toMatchObject({
      format:'json',seed:42,sequence:0,timestampField:'time',
      variableFields:[
        {path:'src_ip',kind:'ipv4'},{path:'username',kind:'username'},{path:'url',kind:'url'},
      ],
    });
    expect(body.source).toContain('192.0.2.10');
    expect(body.source).toContain('example.invalid');
    for(const secret of ['198.51.100.21','API-KEY','password','customer.example','create','sensorIp']) {
      expect(JSON.stringify(body)).not.toContain(secret);
    }
    expect(init.body).not.toContain('approvalId');
  });
  it('does not call backend if preview requires forbidden flags',async()=>{
    const request=fake(response);
    await expect(requestAuthorizedSyntheticPreview({testLab:{...caps.testLab,liveSensorSenderEnabled:true}} as BackendCapabilities,request)).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
  });
  it.each([401,403,404,422,503])('authorization/endpoint error HTTP %s returns no verified event',async status=>{
    await expect(requestAuthorizedSyntheticPreview(caps,fake({error:'PRIVATE_BACKEND_ERROR'},status))).rejects.toThrow(String(status));
  });
  it.each([
    {...response,contract:'parser-studio.synthetic-preview.v2'},
    {...response,safeToSendToSensor:true},
    {...response,runtimeParsingVerified:true},
    {...response,targetSensorVerified:true},
    {...response,format:'cef'},
    {...response,changedPaths:['token','password']},
    {...response,syntheticEvent:JSON.stringify({time:'2026-10-12T02:00:00Z',src_ip:'10.0.0.1',username:'real-customer',url:'https://private',action:'allow'})},
    {...response,syntheticEvent:JSON.stringify({time:'2026-10-12T02:00:00Z',src_ip:'192.0.2.42',username:'synthetic_user_100123',url:'https://synthetic.invalid/synthetic/1234abcd',action:'allow',secret:'foo'})},
    {...response,generatedAt:'secret string'},
    {...response,sequence:1},
  ])('refuses untrusted previews, leaked fields and misleading compatibility status',async wrong=>{
    await expect(requestAuthorizedSyntheticPreview(caps,fake(wrong))).rejects.toThrow();
  });
});
