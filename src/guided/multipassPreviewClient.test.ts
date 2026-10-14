import {describe,it,expect,vi} from 'vitest';
import {requestMultiPassPreview} from './multipassPreviewClient';

describe('opt-in Multi-Pass preview contract',()=>{
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
});
