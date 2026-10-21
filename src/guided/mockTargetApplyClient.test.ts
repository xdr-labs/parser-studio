import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import type {RevisionSummary} from './artifactRevisionClient';
import {getMockApplyStatus,submitMockApply} from './mockTargetApplyClient';

const parser='customized_demo_firewall';
const hash='a'.repeat(64);
const pair:RevisionSummary={
  artifactRevisionId:hash,parserName:parser,projectId:'draft-demo_firewall',
  projectRevision:1,version:'1.0.0',selectedParserPort:6801,
  receiverProtocols:['udp','tcp'],
  fileHashes:{[parser]:hash,[parser+'.conf']:'b'.repeat(64)},
  zipSha256:'c'.repeat(64),createdAt:'2026-10-12T10:00:00.000Z',
  targetImportVerified:false,deploymentPerformed:false,
};
const state={contract:'target-apply-mock.v0.1',mode:'MOCK_ONLY',
  artifactRevisionId:hash,status:'NOT_ATTEMPTED',ephemeral:true,
  realTargetVerified:false,sensorReadyVerified:false,
  targetImportVerified:false,realRuntimeParsingVerified:false};
const proof={artifactRevisionId:hash,fileHashes:pair.fileHashes,name:parser,
  tenant:'offline-owner',origin:'https://offline.invalid',version:'1.0.0',
  selectedParserPort:6801,registration:{status:'API_REGISTERED_READBACK',
    apiReadbackVerified:true,realRuntimeParsingVerified:false,
    sensorReadyVerified:false,targetImportVerified:false},
  mode:'MOCK_ONLY',status:'MOCK_READBACK_VERIFIED',realTargetVerified:false};
const json=(status:number,data:unknown)=>({status,json:async()=>data}) as Response;

describe('P0-LIVE-2 mock-only Apply checkpoint',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('queries only an explicit immutable revision status; never implies real target PASS',async()=>{
    const requester=vi.fn(async()=>json(200,state)) as unknown as typeof fetch;
    await expect(getMockApplyStatus(pair,requester)).resolves.toMatchObject({
      artifactRevisionId:hash,status:'NOT_ATTEMPTED',mode:'MOCK_ONLY'});
    const [url,options]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/target/apply/status?artifactRevisionId='+hash);
    expect(options).toMatchObject({method:'GET',credentials:'same-origin',cache:'no-store'});
    for(const unexpected of [
      {...state,realTargetVerified:true},
      {...state,mode:'LIVE'},
      {...state,apiKey:'unexpected'},
      {...state,artifactRevisionId:'b'.repeat(64)},
    ]){
      const fake=vi.fn(async()=>json(200,unexpected)) as unknown as typeof fetch;
      await expect(getMockApplyStatus(pair,fake)).rejects.toThrow();
    }
  });
  it('fail-closes unconfigured default 403 without issuing any other request',async()=>{
    const requester=vi.fn(async()=>json(403,{error:'TARGET_APPLY_DISABLED'})) as unknown as typeof fetch;
    await expect(getMockApplyStatus(pair,requester)).rejects.toThrow(/unavailable|denied/i);
    await expect(submitMockApply(pair,'TEST-APPROVAL-001',true,requester))
      .rejects.toThrow(/unavailable|denied/i);
    expect(vi.mocked(requester).mock.calls).toHaveLength(2);
  });
  it('requires explicit mock confirmation and operator ID before metadata-only POST',async()=>{
    const requester=vi.fn(async()=>json(200,proof)) as unknown as typeof fetch;
    await expect(submitMockApply(pair,'TEST-APPROVAL-001',true,requester))
      .resolves.toMatchObject({mode:'MOCK_ONLY',status:'MOCK_READBACK_VERIFIED'});
    const [url,opts]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/target/apply');
    expect(opts).toMatchObject({method:'POST',credentials:'same-origin',cache:'no-store'});
    expect(JSON.parse(String(opts?.body))).toEqual({
      artifactRevisionId:hash,expectedName:parser,expectedVersion:'1.0.0',
      approvalId:'TEST-APPROVAL-001',confirmed:true,
    });
    expect(String(opts?.body)).not.toContain('apiKey');
    expect(String(opts?.body)).not.toContain('tenant');
    const count=vi.mocked(requester).mock.calls.length;
    for(const [id,confirm] of [['bad',true],['TEST-APPROVAL-001',false]] as const)
      await expect(submitMockApply(pair,id,confirm,requester)).rejects.toThrow();
    expect(vi.mocked(requester).mock.calls.length).toBe(count);
  });
  it('rejects forged real-target proof, mismatched file hashes, source values, and wrong port',async()=>{
    for(const tampered of [
      {...proof,realTargetVerified:true},
      {...proof,origin:'https://live.example.com'},
      {...proof,fileHashes:{[parser]:'0'.repeat(64),[parser+'.conf']:'b'.repeat(64)}},
      {...proof,selectedParserPort:6800},
      {...proof,registration:{...proof.registration,realRuntimeParsingVerified:true}},
      {...proof,rawLog:'198.51.100.10'},
    ]){
      const requester=vi.fn(async()=>json(200,tampered)) as unknown as typeof fetch;
      await expect(submitMockApply(pair,'TEST-APPROVAL-001',true,requester)).rejects.toThrow();
    }
  });
});
