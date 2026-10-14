"""Deterministic 500-case unseen lexical mutation holdout; not new vendor traffic."""
from collections import Counter
import hashlib,json
from benchmark_security_sources import read_fixtures,reference_json
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting


def evaluate():
    seeds=[]
    for item,raws in read_fixtures():
        for raw in raws:
            if raw.lstrip().startswith(('{','[')):
                tree,_=reference_json(raw)
                seeds.append((item['id'],tree))
    if not seeds:raise ValueError('HOLDOUT_NO_SEEDS')
    total=Counter();families={}
    for index in range(500):
        family,tree=seeds[index%len(seeds)]
        # New layouts and whitespace variants, not new underlying events.
        variant=index%5
        if variant==0:raw=json.dumps(tree,ensure_ascii=False,separators=(',',':'))
        elif variant==1:raw=json.dumps(tree,ensure_ascii=True,indent=2)
        elif variant==2:raw=json.dumps(tree,ensure_ascii=False,indent=1,sort_keys=True)
        elif variant==3:raw=json.dumps(tree,ensure_ascii=True,separators=(', ',': '),sort_keys=True)
        else:raw=json.dumps(tree,ensure_ascii=False,indent=4)
        expected,leaves=reference_json(raw)
        event=parse_security_multipass(raw)
        assert_source_accounting(event)
        gold=Counter((tuple(x.path),json.dumps(x.value,sort_keys=True,ensure_ascii=True),x.start_byte,x.end_byte) for x in leaves)
        actual=Counter()
        for span in event.value_spans:
            path=span.source_segments
            if path is None:continue
            node=event.vendor_fields
            try:
                for segment in path:node=node[segment]
                actual[(tuple(path),json.dumps(node,sort_keys=True,ensure_ascii=True),span.start_byte,span.end_byte)]+=1
            except (KeyError,TypeError,IndexError):actual[(('INVALID',),None,span.start_byte,span.end_byte)]+=1
        counts=Counter(events=1,fields=len(gold),TP=sum((gold&actual).values()),FP=sum((actual-gold).values()),FN=sum((gold-actual).values()),exact=int(expected==event.vendor_fields and gold==actual),raw_preserved=int(event.raw==raw),false_complete=int(event.status=='SOURCE_PARSED' and (expected!=event.vendor_fields or gold!=actual)))
        total.update(counts);families.setdefault(family,Counter()).update(counts)
    return {'contract':'parser-studio.poc.security-lexical-holdout-500.v1','evidence_class':'DERIVED_LEXICAL_MUTATIONS_OF_PREVIOUSLY_SEEN_VENDOR_FIXTURES_NOT_NEW_VENDOR_TRAFFIC','seed_records':len(seeds),'cases':500,'total':dict(total),'families':{k:dict(v) for k,v in sorted(families.items())},'source_values_published':False,'dictionary_attempted':False}

if __name__=='__main__':
    result=evaluate()
    print(json.dumps(result,sort_keys=True))
