"""Value-free massive open-world evaluator and failure clustering."""
from __future__ import annotations
from collections import Counter,defaultdict
import hashlib,json,re
from pathlib import Path

from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'GENERIC_STRUCTURAL_MASSIVE_OPENWORLD_CORPUS_20261015.json'
CACHE=HERE/'.cache/massive_openworld_20261015'

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
        raise ValueError('MASSIVE_PATH_FAMILY_MISMATCH')
    rel=path[len(prefix):].replace('/','__')
    return CACHE/family/rel


def issue_class(event):
    issues='|'.join(event.issues)
    if 'JSON_FIELD_LIMIT' in issues or 'JSON_DEPTH_OR_FIELD_LIMIT' in issues:
        return 'JSON_LIMIT'
    if 'ASA_MESSAGE_BODY_UNPARSED' in issues:
        return 'ASA_BODY'
    if 'UNSUPPORTED_PRI_BODY' in issues:
        return 'PRI_BODY'
    if 'UNSUPPORTED_BSD_BODY' in issues:
        return 'BSD_BODY'
    if 'NO_SUPPORTED_GRAMMAR' in issues:
        return 'NO_GRAMMAR'
    if 'UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION' in issues:
        return 'CSV_UNLABELED'
    if 'RFC5424_TIMESTAMP_INVALID' in issues:
        return 'RFC5424_TIMESTAMP'
    if 'SOURCE_SIZE_OR_NUL_INVALID' in issues:
        return 'SIZE_OR_NUL'
    if 'KV_TOKEN_UNRECOGNIZED' in issues:
        return 'KV_BOUNDARY'
    return 'OTHER'


def shape(raw):
    eq=len(KV_TOKEN.findall(raw))
    commas=raw.count(',')
    semis=raw.count(';')
    ips=len(IPISH.findall(raw))
    quoted=raw.count('"')>=2 or raw.count("'")>=2
    result=[]
    if raw.lstrip().startswith(('{','[')): result.append('JSONISH')
    if PRI.match(raw): result.append('PRI')
    if BSDISH.match(raw): result.append('BSDISH')
    if ISO_SYSLOGISH.match(raw): result.append('ISO_SYSLOGISH')
    if EVENT_CODE.search(raw): result.append('EVENT_CODE')
    if eq>=5: result.append('KV5')
    elif eq>=2: result.append('KV2')
    if commas>=5 and eq>=3: result.append('COMMA_KV')
    if commas>=8 and eq<2: result.append('WIDE_CSV')
    if semis>=5 and eq>=2: result.append('SEMI_KV')
    if ips>=2: result.append('IP2')
    if quoted: result.append('QUOTED')
    if ': ' in raw and eq>=2: result.append('LABEL_KV')
    return '+'.join(result) or 'OTHER'


def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();families={};total=Counter();issues=Counter();syntaxes=Counter()
    clusters=Counter();cluster_families=defaultdict(Counter);largest=[]
    for item in manifest['files']:
        path=local_path(item)
        blob=path.read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('MASSIVE_SOURCE_SHA_CHANGED')
        batch=parse_security_batch(
            blob.decode('utf8','strict'),
            max_events=1000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen: continue
            seen.add(digest)
            event=frame.event;assert_source_accounting(event)
            fam=item['family'];stats=families.setdefault(fam,Counter())
            source_bytes=len(raw.encode())
            for c in (total,stats):
                c['events']+=1;c['raw_preserved']+=event.raw==raw
                c['status_'+event.status]+=1
                c['source_bytes']+=source_bytes
                c['source_fields']+=event.primitive_fields
                c['source_spans']+=len(event.value_spans)
                c['residual_bytes']+=event.residual_bytes
                c['issues']+=len(event.issues)
            syntaxes[event.syntax]+=1
            issues.update(event.issues)
            if event.status!='SOURCE_PARSED':
                cls=issue_class(event); shp=shape(raw)
                key=cls+'|'+shp
                clusters[key]+=1;cluster_families[key][fam]+=1
                largest.append({
                    'event_sha256':digest,'family':fam,'syntax':event.syntax,
                    'issue_class':cls,'shape':shp,'source_bytes':source_bytes,
                    'residual_bytes':event.residual_bytes,
                    'source_spans':len(event.value_spans),
                })
    if len(seen)!=manifest['unique_logical_event_count']:
        raise ValueError(f'MASSIVE_EVENT_COUNT_CHANGED:{len(seen)}')
    for c in [total,*families.values()]:
        c['complete_rate_ppm']=round(1_000_000*c['status_SOURCE_PARSED']/c['events'])
        c['residual_byte_rate_ppm']=round(1_000_000*c['residual_bytes']/c['source_bytes']) if c['source_bytes'] else 0
    cluster_rows=[]
    for key,count in clusters.most_common():
        cluster_rows.append({
            'cluster':key,'events':count,
            'families':dict(cluster_families[key].most_common()),
            'family_count':len(cluster_families[key]),
        })
    result={
        'contract':'parser-studio.poc.massive-openworld-current.v1',
        'corpus_contract':manifest['contract'],
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'top_issues':[list(x) for x in issues.most_common(30)],
        'top_syntaxes':[list(x) for x in syntaxes.most_common(30)],
        'failure_clusters':cluster_rows[:80],
        'largest_residual_events':sorted(largest,key=lambda x:x['residual_bytes'],reverse=True)[:50],
        'raw_published':False,
        'field_semantics_scored':False,
    }
    return result

if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-massive-current.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('TOP_CLUSTERS')
    for row in result['failure_clusters'][:30]:
        print(row)
