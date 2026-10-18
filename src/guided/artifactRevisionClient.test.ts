import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createHash,webcrypto} from 'node:crypto';
import type {GeneratedPair} from './backendClient';
import {registerArtifactRevision,listArtifactRevisions,compareArtifactRevisions,
  retrieveRevisionZip,type RevisionSummary} from './artifactRevisionClient';

const hash=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex');
const parser='customized_demo_firewall',conf=parser+'.conf',project='demo-firewall';
const ruby='# Synthetic Ruby fragment\n',config='<source>\n @type udp\n</source>\n';
const files=[{name:conf,content:config,sha256:hash(config),bytes:Buffer.byteLength(config)},
  {name:parser,content:ruby,sha256:hash(ruby),bytes:Buffer.byteLength(ruby)}];
const fileHashes={[conf]:hash(config),[parser]:hash(ruby)};
const pair:GeneratedPair={contract:'host-customized-pair.v0.1',files,manifest:{
  contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
  engineVerified:false,targetImportVerified:false,projectId:project,projectRevision:1,
  fileHashes,warnings:[],
}};
const zip=new Uint8Array([0x50,0x4b,0x03,0x04,0x01,0x02,0x03,
  0x50,0x4b,0x05,0x06,...Array(18).fill(0)]);
const first:RevisionSummary={artifactRevisionId:'a'.repeat(64),parserName:parser,
  projectId:project,projectRevision:1,version:'1.0.0',selectedParserPort:7501,
  receiverProtocols:['udp'],fileHashes,zipSha256:hash(zip),
  createdAt:'2026-10-12T00:00:00.000Z',targetImportVerified:false,deploymentPerformed:false};
const second:RevisionSummary={...first,artifactRevisionId:'b'.repeat(64),
  version:'2.0.0',createdAt:'2026-10-12T01:00:00.000Z'};
const json=(status:number,value:unknown)=>({status,json:async()=>value}) as Response;
const zipReply=(summary:RevisionSummary,preview=false,bytes=zip)=>({
  status:200,
  headers:new Headers({
    'content-type':'application/zip','content-length':String(bytes.byteLength),
    'content-disposition':'attachment; filename="'+parser+'-r1.zip"',
    'x-parser-artifact-revision':summary.artifactRevisionId,
    'x-parser-zip-sha256':summary.zipSha256,
    ...(preview?{'x-parser-restore-status':'OFFLINE_RESTORE_PREVIEW'}:{}),
  }),
  arrayBuffer:async()=>new Uint8Array(bytes).buffer,
}) as Response;

describe('opt-in owner-scoped offline artifact revision API',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());

  it('registers only a verified DRAFT pair and redacts client-visible revision metadata',async()=>{
    const requester=vi.fn(async()=>json(200,first)) as unknown as typeof fetch;
    await expect(registerArtifactRevision(pair,'1.0.0',7501,requester)).resolves.toEqual(first);
    const [url,opts]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/revisions/register');
    expect(opts).toMatchObject({method:'POST',credentials:'same-origin',cache:'no-store'});
    expect(JSON.parse(String(opts?.body))).toEqual({pair,version:'1.0.0'});
    expect(JSON.stringify(opts)).not.toContain('apiKey');
    expect(JSON.stringify(opts)).not.toContain('198.51.100.10');
  });
  it('rejects unauthorized default 403; never treats a disabled history as enabled',async()=>{
    const requester=vi.fn(async()=>json(403,{error:'REVISION_HISTORY_DISABLED'})) as unknown as typeof fetch;
    await expect(listArtifactRevisions(project,requester)).rejects.toThrow(/access denied|unavailable/i);
    await expect(registerArtifactRevision(pair,'1.0.0',7501,requester)).rejects.toThrow(/access denied|unavailable/i);
  });
  it('lists only an explicit same-origin project and refuses cross-owner/malicious metadata',async()=>{
    const requester=vi.fn(async()=>json(200,{contract:'offline-revision-history.v0.1',
      revisions:[first,second],persistent:false,deploymentPerformed:false})) as unknown as typeof fetch;
    await expect(listArtifactRevisions(project,requester)).resolves.toEqual([first,second]);
    const [url,opts]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/revisions/list?projectId=demo-firewall');
    expect(opts).toMatchObject({method:'GET',credentials:'same-origin'});
    for(const altered of [
      {...first,projectId:'another-owner'}, {...first,ownerId:'private-owner'},
      {...first,fileHashes:{...fileHashes,'apiKey':'top-secret'}},
      {...first,deploymentPerformed:true}, {...first,parserName:'../../attack'},
      {...first,createdAt:'<img src=x onerror=alert(1)>'},
    ]) {
      const fake=vi.fn(async()=>json(200,{contract:'offline-revision-history.v0.1',
        revisions:[altered],persistent:false,deploymentPerformed:false})) as unknown as typeof fetch;
      await expect(listArtifactRevisions(project,fake)).rejects.toThrow();
    }
  });
  it('refuses changed, forged or raw-log-bearing registration replies',async()=>{
    for(const altered of [
      {...first,projectId:'another-owner'},
      {...first,fileHashes:{...fileHashes,[conf]:'0'.repeat(64)}},
      {...first,zipSha256:'not-a-sha'},
      {...first,rawLog:'never display this'},
      {...first,targetImportVerified:true},
    ]) {
      const requester=vi.fn(async()=>json(200,altered)) as unknown as typeof fetch;
      await expect(registerArtifactRevision(pair,'1.0.0',7501,requester)).rejects.toThrow();
    }
  });
  it('returns only verified SHA/port changes and refuses cross-project diff',async()=>{
    const diff={contract:'offline-artifact-diff.v0.1',
      fromRevisionId:first.artifactRevisionId,toRevisionId:second.artifactRevisionId,
      projectId:project,version:{from:'1.0.0',to:'2.0.0',changed:true},
      selectedParserPort:{from:7501,to:7501,changed:false},
      files:[{name:parser,fromSha256:hash(ruby),toSha256:hash(ruby),changed:false},
        {name:conf,fromSha256:hash(config),toSha256:hash(config),changed:false}],
      realTargetVerified:false,appliesToDp:false};
    const requester=vi.fn(async()=>json(200,diff)) as unknown as typeof fetch;
    await expect(compareArtifactRevisions(first,second,requester)).resolves.toEqual(diff);
    expect(JSON.parse(String(vi.mocked(requester).mock.calls[0][1]?.body))).toEqual({
      fromRevisionId:first.artifactRevisionId,toRevisionId:second.artifactRevisionId});
    const denied=vi.fn(async()=>json(404,{error:'REVISION_NOT_FOUND'})) as unknown as typeof fetch;
    await expect(compareArtifactRevisions(first,second,denied)).rejects.toThrow();
    expect(vi.mocked(denied).mock.calls.length).toBe(1);
    await expect(compareArtifactRevisions(first,{...second,projectId:'foreign'},denied)).rejects.toThrow();
    expect(vi.mocked(denied).mock.calls.length).toBe(1);
    const forged=vi.fn(async()=>json(200,{...diff,files:[{...diff.files[0],changed:true},diff.files[1]]})) as unknown as typeof fetch;
    await expect(compareArtifactRevisions(first,second,forged)).rejects.toThrow();
  });
  it('verifies immutable ZIP SHA and preview status without calling apply or altering drafts',async()=>{
    const requester=vi.fn(async()=>zipReply(first)) as unknown as typeof fetch;
    const downloaded=await retrieveRevisionZip(first,null,requester);
    expect(downloaded.filename).toBe(parser+'-r1.zip');
    expect(hash(new Uint8Array(downloaded.bytes))).toBe(first.zipSha256);
    expect(vi.mocked(requester).mock.calls[0][0]).toBe(
      '/api/v1/parser-pairs/revisions/download?artifactRevisionId='+first.artifactRevisionId);
    const preview=vi.fn(async()=>zipReply(first,true)) as unknown as typeof fetch;
    await expect(retrieveRevisionZip(first,second,preview)).resolves.toMatchObject({
      artifactRevisionId:first.artifactRevisionId,previewOnly:true});
    expect(JSON.parse(String(vi.mocked(preview).mock.calls[0][1]?.body))).toEqual({
      previousRevisionId:first.artifactRevisionId,expectedCurrentRevisionId:second.artifactRevisionId});
    for(const tampered of [
      zipReply(first,false,new Uint8Array([...zip,1])),
      zipReply({...first,zipSha256:'0'.repeat(64)}),
      json(403,{error:'REVISION_ACCESS_DENIED'}),
    ]) {
      const fake=vi.fn(async()=>tampered) as unknown as typeof fetch;
      await expect(retrieveRevisionZip(first,null,fake)).rejects.toThrow();
    }
  });
});
