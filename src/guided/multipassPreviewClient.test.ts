import {afterEach,describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {requestMultiPassPreview} from './multipassPreviewClient';

describe('opt-in Multi-Pass preview contract',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('never sends source when input is empty or too large',async()=>{
  const requester=vi.fn();
  await expect(requestMultiPassPreview('',requester as unknown as typeof fetch)).rejects.toThrow();
  await expect(requestMultiPassPreview('x'.repeat(65537),requester as unknown as typeof fetch)).rejects.toThrow();
  expect(requester).not.toHaveBeenCalled();
 });
 it('rejects forged source identity and native verification',async()=>{
  const raw='src=192.0.2.1';
  const base={contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',
   syntax:'KV',sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(raw).length,
   fields:{src:'192.0.2.1'},spans:[{path:'src',startByte:4,endByte:13}],residuals:[],
   issues:[],nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>base});
  await expect(requestMultiPassPreview(raw,requester as typeof fetch)).rejects.toThrow('source mismatch');
  expect(requester).toHaveBeenCalledTimes(1);
  expect(requester.mock.calls[0]?.[1]?.method).toBe('POST');
  const bad=vi.fn().mockResolvedValue({ok:true,json:async()=>({...base,nativeVerified:true})});
  await expect(requestMultiPassPreview(raw,bad as typeof fetch)).rejects.toThrow('Untrusted');
 });
 it('verifies a FortiGate-style KV response even when Web Crypto is unavailable on an HTTP IP preview',async()=>{
  vi.stubGlobal('crypto',{});
  const raw='date=2019-05-10 time=11:37:47 type="traffic" srcip=192.0.2.10 dstip=198.51.100.20 action="close"';
  const value={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),
   sourceBytes:new TextEncoder().encode(raw).length,
   fields:{date:'2019-05-10',time:'11:37:47',type:'traffic',srcip:'192.0.2.10',dstip:'198.51.100.20',action:'close'},
   spans:[{path:'srcip',startByte:51,endByte:61}],residuals:[],issues:[],nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>value});
  await expect(requestMultiPassPreview(raw,requester as typeof fetch)).resolves.toMatchObject({
   status:'SOURCE_PARSED',syntax:'KV',fields:{srcip:'192.0.2.10',action:'close'}});
 });
});
