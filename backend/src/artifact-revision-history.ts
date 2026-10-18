/**
 * Ephemeral, owner-scoped offline review history for exact Ruby/CONF pairs.
 * Nothing here is a target registration, parser rollback or durable store.
 * No HTTP route, filesystem writes, live network calls or credentials.
 */
import {buildArtifactPackage,type ArtifactPackage,
  type ArtifactRevisionManifest} from "./artifact-package.js";
import type {PairExport} from "./types.js";

export class ArtifactRevisionHistoryError extends Error{
  constructor(readonly code:string){super(code);this.name="ArtifactRevisionHistoryError";}
}
const denied=(code:string):never=>{throw new ArtifactRevisionHistoryError(code);};
const ACTOR=/^[A-Za-z0-9_.:@-]{1,128}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const ID=/^[0-9a-f]{64}$/;
const PROJECT=/^[A-Za-z0-9_.-]{1,128}$/;
export type RevisionOwner={ownerId:string;tenant:string};
export type ArtifactRevisionSummary={
  artifactRevisionId:string;
  parserName:string;
  projectId:string;
  projectRevision:number;
  version:string;
  selectedParserPort:number;
  receiverProtocols:readonly ("udp"|"tcp")[];
  fileHashes:Record<string,string>;
  zipSha256:string;
  createdAt:string;
  targetImportVerified:false;
  deploymentPerformed:false;
};
export type ArtifactRevisionDiff={
  contract:"offline-artifact-diff.v0.1";
  fromRevisionId:string;
  toRevisionId:string;
  projectId:string;
  version:{from:string;to:string;changed:boolean};
  selectedParserPort:{from:number;to:number;changed:boolean};
  files:Array<{name:string;fromSha256:string|null;toSha256:string|null;
    changed:boolean}>;
  realTargetVerified:false;
  appliesToDp:false;
};
export type ServerOwnedArtifactRevision={
  /** Only returned to trusted backend code; never serialize this to HTTP. */
  ownerId:string;
  tenant:string;
  pair:PairExport;
  artifact:ArtifactPackage;
};
export type ArtifactRevisionDownload={
  artifactRevisionId:string;
  zip:Buffer;
  zipSha256:string;
  filename:string;
  targetImportVerified:false;
  deploymentPerformed:false;
};
export type OfflineRestorePreview=ArtifactRevisionDownload&{
  status:"OFFLINE_RESTORE_PREVIEW";
  immutableRevisionId:string;
  expectedCurrentRevisionId:string;
  appliesToDp:false;
  realTargetVerified:false;
};
export type ArtifactRevisionHistoryOptions={
  now?:()=>number;
  ttlMs?:number;
  maxRevisions?:number;
};
type Stored={
  owner:RevisionOwner;
  pair:PairExport;
  archive:ArtifactPackage;
  createdAt:number;
};
export class ArtifactRevisionHistory{
  /** Default offline history is volatile; durable stores must opt in. */
  get persistent():boolean{return false;}
  #rows=new Map<string,Stored>();
  #key(actor:RevisionOwner,id:string){
    return actor.tenant+"|"+actor.ownerId+"|"+id;
  }
  #clock:()=>number;
  #ttl:number;
  #max:number;
  constructor(options:ArtifactRevisionHistoryOptions={}){
    this.#clock=options.now??(()=>Date.now());
    this.#ttl=options.ttlMs??86400000;
    this.#max=options.maxRevisions??128;
    if(!Number.isSafeInteger(this.#ttl)||this.#ttl<250||this.#ttl>86400000||
       !Number.isInteger(this.#max)||this.#max<1||this.#max>256)
      denied("REVISION_CONFIGURATION_INVALID");
  }
  #actor(actor:RevisionOwner):void{
    if(!actor||typeof actor.ownerId!=="string"||!ACTOR.test(actor.ownerId)||
       typeof actor.tenant!=="string"||!TENANT.test(actor.tenant))
      denied("REVISION_ACTOR_INVALID");
  }
  #expire(){
    const now=this.#clock();
    for(const [id,row] of this.#rows){
      if(now-row.createdAt>=this.#ttl)this.#rows.delete(id);
    }
  }
  #owned(actor:RevisionOwner,id:string):Stored{
    this.#actor(actor);this.#expire();
    if(typeof id!=="string"||!ID.test(id))denied("REVISION_ID_INVALID");
    const row=this.#rows.get(this.#key(actor,id));
    if(!row||row.owner.ownerId!==actor.ownerId||row.owner.tenant!==actor.tenant)
      return denied("REVISION_NOT_FOUND");
    return row;
  }
  #summary(row:Stored):ArtifactRevisionSummary{
    const m=row.archive.manifest;
    return {
      artifactRevisionId:m.artifactRevisionId,
      parserName:m.parserName,projectId:m.projectId,
      projectRevision:m.projectRevision,version:m.version,
      selectedParserPort:m.selectedParserPort,
      receiverProtocols:[...m.receiverProtocols],fileHashes:{...m.fileHashes},
      zipSha256:row.archive.zipSha256,
      createdAt:new Date(row.createdAt).toISOString(),
      targetImportVerified:false,deploymentPerformed:false,
    };
  }
  #verifiedArchive(row:Stored):ArtifactPackage{
    try{
      const verified=buildArtifactPackage(row.pair,row.archive.manifest.version);
      if(verified.manifest.artifactRevisionId!==
          row.archive.manifest.artifactRevisionId||
         verified.zipSha256!==row.archive.zipSha256||
         !verified.zip.equals(row.archive.zip))
        denied("REVISION_INTEGRITY_UNVERIFIED");
      return verified;
    }catch{return denied("REVISION_INTEGRITY_UNVERIFIED");}
  }
  register(actor:RevisionOwner,pair:PairExport,version:string):ArtifactRevisionSummary{
    this.#actor(actor);this.#expire();
    // This validator checks SHA-256, extensionless Ruby and paired CONF against
    // a reproduced reviewed compiler output. Caller source is never retained.
    const archive=buildArtifactPackage(pair,version);
    const id=archive.manifest.artifactRevisionId;
    if(this.#rows.has(this.#key(actor,id)))denied("REVISION_DUPLICATE");
    if(this.#rows.size>=this.#max)denied("REVISION_CAPACITY_REACHED");
    const saved:Stored={
      owner:{ownerId:actor.ownerId,tenant:actor.tenant},
      pair:structuredClone(pair),
      archive:{zip:Buffer.from(archive.zip),zipSha256:archive.zipSha256,
        filename:archive.filename,
        manifest:structuredClone(archive.manifest)},
      createdAt:this.#clock(),
    };
    this.#rows.set(this.#key(actor,id),saved);
    return this.#summary(saved);
  }
  list(actor:RevisionOwner,projectId:string):ArtifactRevisionSummary[]{
    this.#actor(actor);this.#expire();
    if(typeof projectId!=="string"||!PROJECT.test(projectId))
      denied("REVISION_PROJECT_INVALID");
    return [...this.#rows.values()]
      .filter(row=>row.owner.ownerId===actor.ownerId&&
        row.owner.tenant===actor.tenant&&row.archive.manifest.projectId===projectId)
      .map(row=>this.#summary(row));
  }
  /**
   * Server-only resolver for a separately authenticated Apply coordinator.
   * Rechecks all exact ZIP/CONF/Ruby bytes and tenant/owner on EVERY lookup.
   * Clones all mutable bytes so callers cannot alter stored revisions.
   * No target network connection or Apply operation is implied.
   */
  resolveOwnedRevision(actor:RevisionOwner,id:string):ServerOwnedArtifactRevision{
    const row=this.#owned(actor,id);
    const verified=this.#verifiedArchive(row);
    return {
      ownerId:row.owner.ownerId,tenant:row.owner.tenant,
      pair:structuredClone(row.pair),
      artifact:{
        zip:Buffer.from(verified.zip),zipSha256:verified.zipSha256,
        filename:verified.filename,
        manifest:structuredClone(verified.manifest),
      },
    };
  }
  download(actor:RevisionOwner,id:string):ArtifactRevisionDownload{
    const row=this.#owned(actor,id);
    const pkg=this.#verifiedArchive(row);
    return {artifactRevisionId:id,filename:pkg.filename,
      zip:Buffer.from(pkg.zip),zipSha256:pkg.zipSha256,
      targetImportVerified:false,deploymentPerformed:false};
  }
  diff(actor:RevisionOwner,fromId:string,toId:string):ArtifactRevisionDiff{
    const from=this.#owned(actor,fromId),to=this.#owned(actor,toId);
    const a=from.archive.manifest,b=to.archive.manifest;
    if(a.projectId!==b.projectId)denied("REVISION_PROJECT_MISMATCH");
    // Hash checks before reporting a diff avoid comparing corrupted snapshots.
    this.#verifiedArchive(from);this.#verifiedArchive(to);
    const hashes=[...new Set([
      ...Object.keys(a.fileHashes),...Object.keys(b.fileHashes),
    ])].sort();
    return {contract:"offline-artifact-diff.v0.1",
      fromRevisionId:fromId,toRevisionId:toId,projectId:a.projectId,
      version:{from:a.version,to:b.version,changed:a.version!==b.version},
      selectedParserPort:{from:a.selectedParserPort,to:b.selectedParserPort,
        changed:a.selectedParserPort!==b.selectedParserPort},
      files:hashes.map(name=>({
        name,fromSha256:a.fileHashes[name]??null,
        toSha256:b.fileHashes[name]??null,
        changed:a.fileHashes[name]!==b.fileHashes[name],
      })),
      realTargetVerified:false,appliesToDp:false,
    };
  }
  /** Read-only fallback: never activates, supersedes or deletes an artifact. */
  prepareRestore(actor:RevisionOwner,oldId:string,
    expectedCurrentId:string):OfflineRestorePreview{
    const previous=this.#owned(actor,oldId),current=this.#owned(actor,expectedCurrentId);
    if(previous.archive.manifest.projectId!==current.archive.manifest.projectId)
      denied("REVISION_PROJECT_MISMATCH");
    const projectId=current.archive.manifest.projectId;
    const all=this.list(actor,projectId);
    if(all.at(-1)?.artifactRevisionId!==expectedCurrentId||oldId===expectedCurrentId)
      denied("REVISION_CURRENT_CONFLICT");
    const download=this.download(actor,oldId);
    return {...download,status:"OFFLINE_RESTORE_PREVIEW",
      immutableRevisionId:oldId,expectedCurrentRevisionId:expectedCurrentId,
      appliesToDp:false,realTargetVerified:false};
  }
}
