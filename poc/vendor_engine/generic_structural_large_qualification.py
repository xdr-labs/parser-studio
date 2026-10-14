"""Large frozen-corpus qualification for Generic Structural Parser PoC.

The corpus is frozen before v2 parser changes. Raw fixtures remain in ignored
local caches. This script publishes aggregate counters only.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from benchmark_commercial_security import evaluate as commercial_evaluate
from benchmark_security_sources import reference_json
from generic_structural_poc import EVENT_CODE,parse_generic_structural
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache'
FROZEN=HERE/'GENERIC_STRUCTURAL_LARGE_QUALIFICATION_CORPUS_20261015.json'
PARENT='07cc6ef87992735216beaea27d05567c169ea9e8'
SEED='generic-structural-large-asa-residual-v1'


def _frozen():
    payload=json.loads(FROZEN.read_text())
    if payload['freeze_parent_head']!=PARENT:
        raise ValueError('QUALIFICATION_PARENT_CHANGED')
    if payload['unique_event_count']!=948 or payload['family_count']!=10:
        raise ValueError('QUALIFICATION_DENOMINATOR_CHANGED')
    return payload


def _events():
    manifest=_frozen()
    security=json.loads((HERE/'security-source-manifest.json').read_text())
    seen=set();hashes=[]
    for item in manifest['files']:
        dataset=item['dataset']
        if dataset=='independent_vendor_holdout':
            path=CACHE/'independent_vendor_holdout'/f"{int(item['id']):02d}.raw"
            blob=path.read_bytes();raws=blob.decode('utf8','strict').splitlines()
        elif dataset=='commercial_security_20261014':
            path=CACHE/'commercial_security_20261014'/(str(item['id'])+'.raw')
            blob=path.read_bytes();raws=blob.decode('utf8','strict').splitlines()
        elif dataset=='security-source-manifest':
            source=next(x for x in security['fixtures'] if x['id']==item['id'])
            blob=(CACHE/source['cache_path']).read_bytes()
            text=blob.decode('utf8','strict')
            raws=[text] if source.get('framing')=='SINGLE_MULTILINE_JSON_OBJECT' else text.splitlines()
        else:
            raise ValueError('UNKNOWN_QUALIFICATION_DATASET')
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('QUALIFICATION_SOURCE_SHA_CHANGED')
        for raw in raws:
            if not raw.strip():
                continue
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest);hashes.append(digest)
            yield item['family'],raw
    actual=hashlib.sha256('\n'.join(sorted(hashes)).encode()).hexdigest()
    if actual!=manifest['corpus_event_sha256_set_digest']:
        raise ValueError('QUALIFICATION_EVENT_SET_CHANGED')
    if len(seen)!=manifest['unique_event_count']:
        raise ValueError('QUALIFICATION_EVENT_COUNT_CHANGED')


def _parent_parser():
    source=subprocess.run(
        ['git','show',PARENT+':poc/vendor_engine/generic_structural_poc.py'],
        cwd=HERE.parent.parent,capture_output=True,check=True,timeout=15,
    ).stdout
    directory=tempfile.TemporaryDirectory(prefix='generic-structural-parent-')
    file=Path(directory.name)/'generic_structural_parent.py'
    file.write_bytes(source)
    spec=importlib.util.spec_from_file_location('generic_structural_parent',file)
    module=importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return directory,module.parse_generic_structural


def _span_set(event):
    return {(x.start_byte,x.end_byte) for x in event.value_spans}


def status_eval(parser):
    total=Counter();families={}
    for family,raw in _events():
        stats=families.setdefault(family,Counter())
        baseline=parse_security_multipass(raw)
        candidate=parser(raw)
        assert_source_accounting(candidate)
        expected=_span_set(baseline);actual=_span_set(candidate)
        stats['events']+=1;total['events']+=1
        stats['baseline_'+baseline.status]+=1;total['baseline_'+baseline.status]+=1
        stats['candidate_'+candidate.status]+=1;total['candidate_'+candidate.status]+=1
        stats['raw_preserved']+=candidate.raw==raw;total['raw_preserved']+=candidate.raw==raw
        if baseline.status=='SOURCE_PARSED':
            stats['baseline_complete']+=1;total['baseline_complete']+=1
            exact=candidate.status=='SOURCE_PARSED' and expected==actual
            stats['complete_exact_span_equivalence']+=exact
            total['complete_exact_span_equivalence']+=exact
            stats['complete_divergence']+=not exact;total['complete_divergence']+=not exact
        else:
            stats['baseline_incomplete']+=1;total['baseline_incomplete']+=1
            if candidate.status=='SOURCE_PARSED':
                stats['incomplete_promoted']+=1;total['incomplete_promoted']+=1
                stats['promoted_extra_spans']+=len(actual-expected)
                total['promoted_extra_spans']+=len(actual-expected)
                stats['promoted_missing_baseline_spans']+=len(expected-actual)
                total['promoted_missing_baseline_spans']+=len(expected-actual)
    total['candidate_complete_rate_ppm']=round(
        1_000_000*total['candidate_SOURCE_PARSED']/total['events']
    )
    total['baseline_complete_rate_ppm']=round(
        1_000_000*total['baseline_SOURCE_PARSED']/total['events']
    )
    return {
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
    }


def _commercial_stats(parser):
    result=commercial_evaluate(parser)
    keys=(
        'all_events','reference_scored_events','reference_excluded_events',
        'gold_fields','TP','FP','FN','precision','recall','f1',
        'exact_all_field_events','SOURCE_PARSED','PARTIAL',
    )
    total={k:result['total'].get(k,0) for k in keys}
    families={}
    for row in result['families']:
        families[row['family']]={k:row.get(k,0) for k in keys}
    return {'total':total,'families':families}


def _json_actual(event):
    output=Counter()
    for span in event.value_spans:
        path=span.source_segments
        if path is None:
            continue
        value=event.vendor_fields
        try:
            for key in path:
                value=value[key]
        except (KeyError,IndexError,TypeError):
            output[(('INVALID',),'INVALID','INVALID',span.start_byte,span.end_byte)]+=1
            continue
        output[(tuple(path),type(value).__name__,
                json.dumps(value,ensure_ascii=True,sort_keys=True),
                span.start_byte,span.end_byte)]+=1
    return output


def json_gold_eval():
    total=Counter();families={}
    allowed={'aws_waf','suricata','sentinel_one','crowdstrike'}
    for family,raw in _events():
        if family not in allowed:
            continue
        try:
            tree,leaves=reference_json(raw)
        except (ValueError,json.JSONDecodeError):
            continue
        candidate=parse_generic_structural(raw)
        assert_source_accounting(candidate)
        expected=Counter(
            (tuple(x.path),type(x.value).__name__,
             json.dumps(x.value,ensure_ascii=True,sort_keys=True),
             x.start_byte,x.end_byte)
            for x in leaves
        )
        actual=_json_actual(candidate)
        stats=Counter(
            events=1,fields=len(expected),
            TP=sum((expected&actual).values()),
            FP=sum((actual-expected).values()),
            FN=sum((expected-actual).values()),
            exact=int(expected==actual and candidate.vendor_fields==tree),
            false_complete=int(
                candidate.status=='SOURCE_PARSED'
                and not(expected==actual and candidate.vendor_fields==tree)
            ),
        )
        families.setdefault(family,Counter()).update(stats);total.update(stats)
    tp,fp,fn=total['TP'],total['FP'],total['FN']
    total['f1']=round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None
    return {
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
    }


def asa_lower_bound_eval(parser):
    total=Counter()
    for family,raw in _events():
        if family!='cisco_asa':
            continue
        baseline=parse_security_multipass(raw);candidate=parser(raw)
        expected=_span_set(baseline);actual=_span_set(candidate)
        total['events']+=1
        total['baseline_source_backed_spans']+=len(expected)
        total['candidate_spans']+=len(actual)
        total['TP_vs_baseline']+=len(expected&actual)
        total['FP_vs_baseline']+=len(actual-expected)
        total['FN_vs_baseline']+=len(expected-actual)
        total['candidate_SOURCE_PARSED']+=candidate.status=='SOURCE_PARSED'
        total['candidate_PARTIAL']+=candidate.status=='PARTIAL'
        total['candidate_RAW_ONLY']+=candidate.status=='RAW_ONLY'
        total['event_code_events']+='GENERIC_EVENT_CODE' in candidate.syntax
    denominator=total['baseline_source_backed_spans']
    total['baseline_span_recall']=round(
        total['TP_vs_baseline']/denominator,6
    ) if denominator else None
    return dict(total)


def asa_residual_template_eval():
    try:
        from residual_miner import miner,aligned_candidate
    except ImportError:
        return {'available':False,'reason':'DRAIN3_OPTIONAL_DEPENDENCY_MISSING'}
    rows=[]
    for family,raw in _events():
        if family=='cisco_asa':
            digest=hashlib.sha256(raw.encode()).hexdigest()
            rows.append((digest,raw))
    rows.sort(key=lambda x:hashlib.sha256((SEED+'|'+x[0]).encode()).hexdigest())
    cutoff=round(len(rows)*0.6)
    train,holdout=rows[:cutoff],rows[cutoff:]
    model=miner('typed')
    for _digest,raw in train:
        model.add_log_message(raw)
    counts=Counter(
        train_records=len(train),holdout_records=len(holdout),
        clusters=len(model.drain.clusters),
    )
    for _digest,raw in holdout:
        match=model.match(raw,full_search_strategy='always')
        if match is None:
            counts['unmatched']+=1
            continue
        counts['matched']+=1
        aligned=aligned_candidate(
            match.get_template(),raw,0,raw,match.size
        )
        counts['status_'+aligned['status']]+=1
        counts['candidate_spans']+=len(aligned.get('captures',[]))
    return {
        'available':True,
        'seed':SEED,
        **dict(counts),
        'automatic_apply_allowed':False,
        'semantic_names_inferred':False,
    }


def asa_shape_recipe_eval():
    """Train-only source-shape routing; still candidate-only, never automatic."""
    try:
        from residual_miner import miner,aligned_candidate
    except ImportError:
        return {'available':False,'reason':'DRAIN3_OPTIONAL_DEPENDENCY_MISSING'}
    rows=[]
    for family,raw in _events():
        if family!='cisco_asa':
            continue
        digest=hashlib.sha256(raw.encode()).hexdigest()
        matches=list(EVENT_CODE.finditer(raw))
        code=matches[0].group(3) if len(matches)==1 else None
        rows.append((digest,raw,code))
    rows.sort(key=lambda x:hashlib.sha256((SEED+'|'+x[0]).encode()).hexdigest())
    cutoff=round(len(rows)*0.6)
    train,holdout=rows[:cutoff],rows[cutoff:]
    groups={}
    for _digest,raw,code in train:
        if code is not None:
            groups.setdefault(code,[]).append(raw)
    models={}
    for code,examples in groups.items():
        if len(examples)<2:
            continue
        model=miner('typed')
        for raw in examples:
            model.add_log_message(raw)
        models[code]=model
    counts=Counter(
        models=len(models),
        holdout_records=len(holdout),
        routable=sum(code in models for _digest,_raw,code in holdout),
    )
    lower=Counter()
    for _digest,raw,code in holdout:
        baseline=parse_security_multipass(raw)
        generic=parse_generic_structural(raw)
        expected=_span_set(baseline)
        generic_spans=_span_set(generic)
        combined=set(generic_spans)
        lower['events']+=1
        lower['baseline_spans']+=len(expected)
        lower['generic_overlap']+=len(expected&generic_spans)
        lower['generic_missing']+=len(expected-generic_spans)
        if code not in models:
            counts['unroutable']+=1
        else:
            match=models[code].match(raw,full_search_strategy='always')
            if match is None:
                counts['routed_unmatched']+=1
            else:
                counts['matched']+=1
                aligned=aligned_candidate(
                    match.get_template(),raw,0,raw,match.size
                )
                counts['status_'+aligned['status']]+=1
                spans={
                    (x['start_byte'],x['end_byte'])
                    for x in aligned.get('captures',[])
                }
                counts['candidate_spans']+=len(spans)
                lower['template_overlap']+=len(expected&spans)
                lower['template_extra']+=len(spans-expected)
                combined|=spans
        lower['combined_overlap']+=len(expected&combined)
        lower['combined_missing']+=len(expected-combined)
    return {
        'available':True,
        'seed':SEED,
        'routing':dict(counts),
        'baseline_lower_bound':dict(lower),
        'automatic_apply_allowed':False,
        'semantic_names_inferred':False,
    }


def run():
    with_parent,parent=_parent_parser()
    try:
        parent_status=status_eval(parent)
        parent_asa=asa_lower_bound_eval(parent)
    finally:
        with_parent.cleanup()
    current_status=status_eval(parse_generic_structural)
    commercial_current=_commercial_stats(parse_generic_structural)
    commercial_baseline=_commercial_stats(parse_security_multipass)
    result={
        'contract':'parser-studio.poc.generic-structural-large-qualification.v1',
        'frozen_corpus_contract':_frozen()['contract'],
        'corpus_events':948,
        'product_families':10,
        'field_semantics_scored':False,
        'parent_candidate_head':PARENT,
        'parent_candidate_status':parent_status,
        'current_candidate_status':current_status,
        'independent_commercial_gold':{
            'baseline':commercial_baseline,
            'candidate':commercial_current,
        },
        'independent_json_gold':json_gold_eval(),
        'asa_parent_lower_bound':parent_asa,
        'asa_current_lower_bound':asa_lower_bound_eval(parse_generic_structural),
        'asa_residual_template':asa_residual_template_eval(),
        'asa_shape_routed_recipe':asa_shape_recipe_eval(),
        'raw_published':False,
        'native_verified':False,
        'product_integrated':False,
    }
    return result


if __name__=='__main__':
    result=run()
    path=HERE/'generic-structural-large-qualification-summary.json'
    path.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    total=result['current_candidate_status']['total']
    print('LARGE_STATUS',total)
    print('COMMERCIAL_GOLD',result['independent_commercial_gold']['candidate']['total'])
    print('JSON_GOLD',result['independent_json_gold']['total'])
    print('ASA_PARENT',result['asa_parent_lower_bound'])
    print('ASA_CURRENT',result['asa_current_lower_bound'])
    print('ASA_RESIDUAL_TEMPLATE',result['asa_residual_template'])
    print('ASA_SHAPE_RECIPE',result['asa_shape_routed_recipe'])
