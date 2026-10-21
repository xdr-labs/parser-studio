import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';
import type { GeneratedPair } from './backendClient';
import { packageGeneratedPair, assertPackageCapability } from './artifactPackageClient';
import type { BackendCapabilities } from './backendCapabilities';

const sha=(s:string|Uint8Array)=>createHash('sha256').update(s).digest('hex');
const downloads={
  individualGeneratedFiles:true, zipWithManifest:true,
  requiresDpConnection:false, requiresApiKey:false, autoDeploys:false,
  exactArtifactRevision:true,
};
const capabilities={downloads} as unknown as BackendCapabilities;
const oldServer={} as BackendCapabilities;
const conf='<source>\n  @type udp\n</source>\n';
const ruby='# synthetic compiled parser\n';
const confName='customized_demo_firewall.conf',parserName='customized_demo_firewall';
const pair:GeneratedPair={
  contract:'host-customized-pair.v0.1',
  files:[
    {name:confName,content:conf,sha256:sha(conf),bytes:Buffer.byteLength(conf)},
    {name:parserName,content:ruby,sha256:sha(ruby),bytes:Buffer.byteLength(ruby)},
  ],
  manifest:{
    contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
    engineVerified:false,targetImportVerified:false,
    projectRevision:1,projectId:'demo-firewall',
    fileHashes:{[confName]:sha(conf),[parserName]:sha(ruby)},
    warnings:['Unverified target compatibility'],
  },
};
const zip=new Uint8Array([0x50,0x4b,0x03,0x04,0x10,0x20,0x30,0x40,0x50,0x4b,0x05,0x06,...Array(18).fill(0)]);
const response=(overrides?:{status?:number;hash?:string;name?:string;mime?:string;size?:number;port?:string})=>({
  status:overrides?.status??200,
  headers:new Headers({
    'content-type':overrides?.mime??'application/zip',
    'content-length':String(overrides?.size??zip.byteLength),
    'content-disposition':'attachment; filename="'+(overrides?.name??'customized_demo_firewall-r1.zip')+'"',
    'x-parser-artifact-revision':'a'.repeat(64),
    'x-parser-listener-port':overrides?.port??'6801',
    'x-parser-zip-sha256':overrides?.hash??sha(zip),
  }),
  arrayBuffer:async()=>new Uint8Array(zip).buffer,
}) as Response;

describe('explicit offline ZIP bundle packaging using reviewed same-origin backend',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('requires exact capability flags and never assumes old backend supports packaging',()=>{
    expect(()=>assertPackageCapability(capabilities)).not.toThrow();
    expect(()=>assertPackageCapability(oldServer)).toThrow();
    for(const bad of [
      {...downloads,autoDeploys:true},
      {...downloads,requiresApiKey:true},
      {...downloads,zipWithManifest:false},
      {...downloads,exactArtifactRevision:false},
    ]) expect(()=>assertPackageCapability({downloads:bad} as unknown as BackendCapabilities)).toThrow();
  });
  it('POSTs only already-generated DRAFT pair, checking ZIP SHA-256/port/revision',async()=>{
    const requester=vi.fn(async()=>response()) as unknown as typeof fetch;
    const result=await packageGeneratedPair(pair,'1.0.0',capabilities,6801,requester);
    expect(result).toMatchObject({filename:'customized_demo_firewall-r1.zip',
      size:zip.byteLength,sha256:sha(zip),artifactRevisionId:'a'.repeat(64),listenerPort:6801});
    expect(result.bytes.byteLength).toBe(zip.byteLength);
    const [url,options]=(requester as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/package');
    expect(options).toMatchObject({method:'POST',cache:'no-store',credentials:'same-origin'});
    expect(options.headers['Content-Type']).toBe('application/json');
    const request=JSON.parse(options.body as string);
    expect(request).toEqual({pair,version:'1.0.0'});
    expect(JSON.stringify(request)).not.toContain('198.51.100.10');
  });
  it.each(['../bad','1.0.0/../../','','v'.repeat(65)])(
    'rejects unsafe package version %s without HTTP request',async version=>{
      const requester=vi.fn(async()=>response()) as unknown as typeof fetch;
      await expect(packageGeneratedPair(pair,version,capabilities,6801,requester)).rejects.toThrow();
      expect(requester).not.toHaveBeenCalled();
    },
  );
  it('rejects tampered or falsely verified pair before sending',async()=>{
    const requester=vi.fn(async()=>response()) as unknown as typeof fetch;
    for(const broken of [
      {...pair,manifest:{...pair.manifest,targetImportVerified:true}},
      {...pair,files:pair.files.map((f,i)=>i===0?{...f,sha256:'f'.repeat(64)}:f)},
      {...pair,files:pair.files.map((f,i)=>i===0?{...f,bytes:99999}:f)},
      {...pair,manifest:{...pair.manifest,fileHashes:{...pair.manifest.fileHashes,[confName]:'0'.repeat(64)}}},
      {...pair,files:pair.files.map((f,i)=>i===0?{...f,name:'../bad.conf'}:f)},
    ]) await expect(packageGeneratedPair(broken as GeneratedPair,'1.0.0',capabilities,6801,requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
  });
  it.each([
    {hash:'0'.repeat(64)},{name:'../../malware.zip'},{mime:'application/json'},
    {size:2*1024*1024+1},{size:33},{port:'80'},{port:'99999'},{status:422},
  ])('refuses inconsistent binary headers, status and content',async modified=>{
    const requester=vi.fn(async()=>response(modified)) as unknown as typeof fetch;
    await expect(packageGeneratedPair(pair,'1.0.0',capabilities,6801,requester)).rejects.toThrow();
  });
  it('requires WebCrypto; never permits unverified file download',async()=>{
    vi.stubGlobal('crypto',null);
    const requester=vi.fn(async()=>response()) as unknown as typeof fetch;
    await expect(packageGeneratedPair(pair,'1.0.0',capabilities,6801,requester)).rejects.toThrow(/SHA-256|secure/i);
    expect(requester).not.toHaveBeenCalled();
  });
});
