"""Finish existing Zeek scalar-metadata comparison on exact current baseline."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
ENGINE=(ROOT/'.cache/latest-baseline/poc/vendor_engine').resolve()
sys.path.insert(0,str(ENGINE))
import source_parse
assert Path(source_parse.__file__).resolve().parent==ENGINE
sys.path.insert(0,str(ROOT))
import benchmark
assert Path(benchmark.parse_source.__code__.co_filename).resolve().parent==ENGINE

if __name__=='__main__':
    report=benchmark.external_benchmark()
    report['comparison_base']='2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03'
    report['baseline_import_path']=str(Path(source_parse.__file__).resolve())
    report['candidate_sha256']=hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest()
    report['evaluation_class']='RESUMED_PREVIOUSLY_ACQUIRED_SOURCE_NOT_NEW_UNTOUCHED_VALIDATION'
    report['note']='Metadata native-name metrics and unnamed value/span metrics are both retained; no conflation.'
    (ROOT/'zeek-resumed-summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    for mode in ('baseline','dialect_only','metadata_only'):
        obj=report['overall'][mode]
        print(mode,'events',obj['events'],'native',obj['exact_native_key_value_byte_span'],
              'value_span',obj['exact_value_byte_span_without_field_name'])
    print('ZEEK_INPUT_LEDGER',{k:sum(g[k] for g in report['groups'].values()) for k in ('physical_records','metadata_records','data_records','train_records','holdout_records','reference_metadata_retained_as_raw')})
