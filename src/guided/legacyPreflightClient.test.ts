import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';
import type { GeneratedPair } from './backendClient';
import { prepareLegacyUploadPlan } from './legacyPreflightClient';

const digest=(data:string)=>createHash('sha256').update(data).digest('hex');
const name='customized_demo_firewall',tenant='synthetic-tenant';
const conf='<source>\n  @type udp\n  port 7501\n</source>\n';
const ruby='# synthetic parser (non-executable fixture)\n';
const pair:GeneratedPair={
  contract:'host-customized-pair.v0.1',
  files:[
    {name:name+'.conf',content:conf,sha256:digest(conf),bytes:Buffer.byteLength(conf)},
    {name,content:ruby,sha256:digest(ruby),bytes:Buffer.byteLength(ruby)},
  ],
  manifest:{contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
    projectId:'demo-firewall',projectRevision:1,engineVerified:false,targetImportVerified:false,
    fileHashes:{[name+'.conf']:digest(conf),[name]:digest(ruby)},warnings:[]},
};
const response={
  contract:'stellar-legacy-poc.v0.1',name,tenant,version:'1.0.0',port:7501,
  filenames:[name,name+'.conf'],
  proof:{parserSha256:digest(ruby),confSha256:digest(conf),
    status:'DRAFT',targetImportVerified:false,runtimeParsingVerified:false},
  testOnlyWriteEligible:false,apiRegistrationVerified:false,
  runtimeParsingVerified:false,targetImportVerified:false,
};
const fake=(body:unknown,status=200)=>vi.fn(async()=>({status,json:async()=>body})) as unknown as typeof fetch;

describe('read-only Legacy POC upload preflight, never registration or deployment',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('POSTs only the verified generated pair, tenant and version after explicit request',async()=>{
    const requester=fake(response);
    const result=await prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,requester);
    expect(result).toMatchObject({name,tenant,version:'1.0.0',port:7501,matchedHashes:true,
      testOnlyWriteEligible:false,targetImportVerified:false,runtimeParsingVerified:false,
      apiRegistrationVerified:false,deploymentPerformed:false});
    expect(result.parserHash).toBe(digest(ruby));
    expect(result.confHash).toBe(digest(conf));
    expect(JSON.stringify(result)).not.toContain('synthetic parser');
    const [url,init]=(requester as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/stellar/legacy/prepare');
    expect(init).toMatchObject({method:'POST',cache:'no-store',credentials:'same-origin'});
    expect(init.headers['Content-Type']).toBe('application/json');
    const input=JSON.parse(init.body);
    expect(input).toEqual({pair,tenant,version:'1.0.0'});
    expect(init.body).not.toContain('198.51.100.10');
    expect(init.body).not.toContain('apiKey');
    expect(init.body).not.toContain('confirmed');
  });
  it('accepts a backend test-only eligibility flag without turning it into upload approval',async()=>{
    const r=await prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,
      fake({...response,testOnlyWriteEligible:true}));
    expect(r.testOnlyWriteEligible).toBe(true);
    expect(r.deploymentPerformed).toBe(false);
    expect(r.targetImportVerified).toBe(false);
  });
  it.each(['../tenant','foo bar','','secret/tenant','t'.repeat(129)])('rejects unsafe tenant input %s without HTTP',async t=>{
    const requester=fake(response);
    await expect(prepareLegacyUploadPlan(pair,t,'1.0.0',7501,requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
  });
  it.each(['../bad','bad version','','v'.repeat(65)])('rejects unsafe version input %s without HTTP',async version=>{
    const requester=fake(response);
    await expect(prepareLegacyUploadPlan(pair,tenant,version,7501,requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
  });
  it('rejects corrupted or mismatched source pair/receiver port before any API call',async()=>{
    const requester=fake(response);
    for(const corrupted of [
      {...pair,files:pair.files.map((x,i)=>i===0?{...x,content:x.content+'BAD'}:x)},
      {...pair,files:pair.files.map((x,i)=>i===0?{...x,sha256:'0'.repeat(64)}:x)},
      {...pair,manifest:{...pair.manifest,targetImportVerified:true}},
      {...pair,manifest:{...pair.manifest,fileHashes:{...pair.manifest.fileHashes,[name]:'0'.repeat(64)}}},
    ]) await expect(prepareLegacyUploadPlan(corrupted as GeneratedPair,tenant,'1.0.0',7501,requester)).rejects.toThrow();
    await expect(prepareLegacyUploadPlan(pair,tenant,'1.0.0',80,requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
  });
  it.each([
    {...response,port:9999},
    {...response,tenant:'other-tenant'},
    {...response,version:'2.0.0'},
    {...response,name:'customized_malicious'},
    {...response,filenames:['../unsafe',name+'.conf']},
    {...response,proof:{...response.proof,parserSha256:'0'.repeat(64)}},
    {...response,proof:{...response.proof,targetImportVerified:true}},
    {...response,apiRegistrationVerified:true},
    {...response,targetImportVerified:true},
    {...response,runtimeParsingVerified:true},
    {...response,proof:{...response.proof,runtimeParsingVerified:true}},
    {...response,unknownSecret:'sensitive'},
  ])('fails closed on misleading response metadata',async bad=>{
    await expect(prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,fake(bad))).rejects.toThrow();
  });
  it('backend missing endpoint, unconfigured, invalid JSON or WebCrypto results never imply approval',async()=>{
    for(const status of [403,404,422,503]){
      await expect(prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,
        fake({error:'DENIED'},status))).rejects.toThrow(String(status));
    }
    const invalid=vi.fn(async()=>({status:200,json:async()=>{throw Error('invalid');}})) as unknown as typeof fetch;
    await expect(prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,invalid)).rejects.toThrow();
    vi.stubGlobal('crypto',null);
    const requester=fake(response);
    await expect(prepareLegacyUploadPlan(pair,tenant,'1.0.0',7501,requester)).rejects.toThrow(/SHA-256|secure/i);
    expect(requester).not.toHaveBeenCalled();
  });
});
