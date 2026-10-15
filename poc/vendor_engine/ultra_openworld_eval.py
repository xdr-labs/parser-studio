"""Value-free ultra open-world evaluator for frozen 8,076-event corpus."""
from __future__ import annotations

from collections import Counter,defaultdict
import hashlib,json,re
from pathlib import Path

from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'GENERIC_STRUCTURAL_ULTRA_OPENWORLD_CORPUS_20261015.json'
CACHE=HERE/'.cache/ultra_openworld_20261015'

KV_TOKEN=re.compile(r'(?<!\S)[A-Za-z_][A-Za-z0-9_.:/# -]{0,63}\s*=\s*')
EVENT_CODE=re.compile(r'%[A-Z][A-Z0-9_-]{1,31}-\d{1,2}-\d{3,8}:')
IPISH=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5}|/\d{1,5})?')
PRI=re.compile(r'^<\d{1,3}>')
BSDISH=re.compile(r'^(?:<\d{1,3}>)?[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2}\b')
ISO_SYSLOGISH=re.compile(r'^<\d{1,3}>\d{4}-\d{2}-\d{2}[ T]')

def local_path(item):
    family=item['family']
    prefix=f'packages/{family}/'
    path=item['path']
    if not path.startswith(prefix):
        raise ValueError('ULTRA_PATH_FAMILY_MISMATCH')
    rel=path[len(prefix):].replace('/','__')
    return CACHE/family/rel

def issue_class(event):
    issues='|'.join(event.issues)
    for needle,label in (
        ('JSON_FIELD_LIMIT','JSON_LIMIT'),
        ('JSON_DEPTH_OR_FIELD_LIMIT','JSON_LIMIT'),
        ('ASA_MESSAGE_BODY_UNPARSED','ASA_BODY'),
        ('UNSUPPORTED_PRI_BODY','PRI_BODY'),
        ('UNSUPPORTED_BSD_BODY','BSD_BODY'),
        ('NO_SUPPORTED_GRAMMAR','NO_GRAMMAR'),
        ('UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION','CSV_UNLABELED'),
        ('RFC5424_TIMESTAMP_INVALID','RFC5424_TIMESTAMP'),
        ('SOURCE_SIZE_OR_NUL_INVALID','SIZE_OR_NUL'),
        ('KV_TOKEN_UNRECOGNIZED','KV_BOUNDARY'),
    ):
        if needle in issues:
            return label
    return 'OTHER'

def shape(raw):
    eq=len(KV_TOKEN.findall(raw));commas=raw.count(',');semis=raw.count(';')
    ips=len(IPISH.findall(raw));quoted=raw.count('"')>=2 or raw.count("'")>=2
    result=[]
    if raw.lstrip().startswith(('{','[')):result.append('JSONISH')
    if PRI.match(raw):result.append('PRI')
    if BSDISH.match(raw):result.append('BSDISH')
    if ISO_SYSLOGISH.match(raw):result.append('ISO_SYSLOGISH')
    if EVENT_CODE.search(raw):result.append('EVENT_CODE')
    if eq>=5:result.append('KV5')
    elif eq>=2:result.append('KV2')
    if commas>=5 and eq>=3:result.append('COMMA_KV')
    if commas>=8 and eq<2:result.append('WIDE_CSV')
    if semis>=5 and eq>=2:result.append('SEMI_KV')
    if ips>=2:result.append('IP2')
    if quoted:result.append('QUOTED')
    if ': ' in raw and eq>=2:result.append('LABEL_KV')
    return '+'.join(result) or 'OTHER'

def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();families={};total=Counter();issues=Counter();syntaxes=Counter()
    clusters=Counter();cluster_families=defaultdict(Counter);largest=[]
    exceptions=Counter()
    for index,item in enumerate(manifest['files'],1):
        path=local_path(item);blob=path.read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('ULTRA_SOURCE_SHA_CHANGED')
        batch=parse_security_batch(
            blob.decode('utf8','strict'),max_events=10000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw;digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest);fam=item['family'];stats=families.setdefault(fam,Counter())
            source_bytes=len(raw.encode())
            try:
                event=frame.event;assert_source_accounting(event)
            except Exception as exc:
                total['exceptions']+=1;stats['exceptions']+=1
                exceptions[type(exc).__name__+':'+str(exc)]+=1
                continue
            for c in (total,stats):
                c['events']+=1;c['raw_preserved']+=event.raw==raw
                c['status_'+event.status]+=1;c['source_bytes']+=source_bytes
                c['source_fields']+=event.primitive_fields
                c['source_spans']+=len(event.value_spans)
                c['residual_bytes']+=event.residual_bytes
                c['issues']+=len(event.issues)
            syntaxes[event.syntax]+=1;issues.update(event.issues)
            if event.status!='SOURCE_PARSED':
                cls=issue_class(event);shp=shape(raw);key=cls+'|'+shp
                clusters[key]+=1;cluster_families[key][fam]+=1
                largest.append({
                    'event_sha256':digest,'family':fam,'syntax':event.syntax,
                    'issue_class':cls,'shape':shp,'source_bytes':source_bytes,
                    'residual_bytes':event.residual_bytes,
                    'source_spans':len(event.value_spans),
                })
        if index%100==0:
            print('PROGRESS',index,'/',len(manifest['files']),'events',len(seen),flush=True)
    if len(seen)!=manifest['unique_logical_event_count']:
        raise ValueError(f"ULTRA_EVENT_COUNT_CHANGED:{len(seen)}")
    for c in [total,*families.values()]:
        c['complete_rate_ppm']=round(1_000_000*c['status_SOURCE_PARSED']/c['events'])
        c['residual_byte_rate_ppm']=round(1_000_000*c['residual_bytes']/c['source_bytes']) if c['source_bytes'] else 0
    result={
        'contract':'parser-studio.poc.ultra-openworld-baseline.v1',
        'corpus_contract':manifest['contract'],
        'parser_head':'cbf18695d605452a3163521d2bd7a7a6b93b0f1c',
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'top_issues':[list(x) for x in issues.most_common(40)],
        'top_syntaxes':[list(x) for x in syntaxes.most_common(40)],
        'failure_clusters':[
            {'cluster':key,'events':count,
             'families':dict(cluster_families[key].most_common()),
             'family_count':len(cluster_families[key])}
            for key,count in clusters.most_common(120)
        ],
        'largest_residual_events':sorted(
            largest,key=lambda x:x['residual_bytes'],reverse=True
        )[:80],
        'exceptions':dict(exceptions),
        'raw_published':False,
        'field_semantics_scored':False,
    }
    return result

if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-ultra-openworld-baseline.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('TOP_CLUSTERS')
    for row in result['failure_clusters'][:30]:
        print(row)
