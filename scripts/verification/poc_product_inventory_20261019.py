#!/usr/bin/env python3
"""Reproducible metadata-only PoC-to-product code-path inventory; never reads private log content."""
from __future__ import annotations
import ast
import hashlib
import json
import pathlib
import re
import subprocess
from datetime import date

ROOT=pathlib.Path(__file__).resolve().parents[2]
HOME=ROOT.parent
OUT=ROOT/'docs/verification/poc-product-inventory-20261019.json'
GRAMMARS={
    'syslog_envelope':(['security_envelope.py','structured_source.py'],['syslogEnvelope.ts','syslogStream.ts']),
    'rfc6587_octet_and_nul':(['security_framing.py'],['syslogStream.ts','securityEventBreaker.ts']),
    'json_typed_spans':(['source_parse.py','security_framing.py'],['jsonBatch.ts','jsonTextSequence.ts']),
    'rfc7464_json_seq':(['security_framing.py'],['jsonTextSequence.ts','securityEventBreaker.ts']),
    'gelf_tcp':(['security_framing.py'],['gelfTcp.ts','securityEventBreaker.ts']),
    'ndjson':(['security_framing.py'],['ndjsonStream.ts','securityEventBreaker.ts']),
    'cef_grammar':(['security_cef.py','structured_source.py'],['structuredFamilies.ts']),
    'leef_grammar':(['security_leef.py','structured_source.py'],['structuredFamilies.ts']),
    'kv_quotes_duplicates':(['source_kv.py','source_parse.py'],['sourceKv.ts','kvParser.ts']),
    'csv_rfc4180':(['security_framing.py','engine.py'],['csvStructural.ts','rfc4180Csv.ts']),
    'w3c_declared_schema':(['security_framing.py'],['w3cTabular.ts','securityInputPipeline.ts']),
    'zeek_declared_schema':(['security_framing.py'],['zeekTabular.ts','securityEventBreaker.ts']),
    'journal_export':(['security_framing.py'],['journalExport.ts','securityEventBreaker.ts']),
    'linux_audit_group':(['security_framing.py'],['linuxAuditStream.ts','securityEventBreaker.ts']),
    'container_cri_docker':(['security_framing.py'],['containerLogFraming.ts','securityEventBreaker.ts']),
    'mixed_format_arbitration':(['source_parse.py','bounded_funnel.py'],['securityInputPipeline.ts','securityEventBreaker.ts']),
    'utf8_original_spans':(['source_parse.py','multipass_contract.py'],['w3cTabular.ts','securityInputPipeline.ts']),
    'relay_prefix_declared':(['source_parse.py'],['manualSourceBoundary.ts']),
    'multitype_mapping':(['multipass_contract.py'],['eventTypeProfiles.ts']),
    'stellar_dictionary':(['stellar_dictionary.py'],['dictionaryMapping.ts']),
    'compiler_status_gating':(['multipass_preview_api.py'],['genericStructuralAutoDraft.ts']),
}
def shell(*args):
    return subprocess.run(args,cwd=ROOT,text=True,capture_output=True,check=False).stdout.strip()
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def safe_git_ref(p):
    r=subprocess.run(['git','-C',str(p),'rev-parse','--short=12','HEAD'],text=True,capture_output=True)
    return r.stdout.strip() if r.returncode==0 else None
def relevant(p):
    return p.suffix in {'.ts','.tsx','.py'} and p.name not in {'__init__.py'}
def imports_ts(p):
    try:s=p.read_text(errors='replace')
    except OSError:return []
    return re.findall(r"""(?:from\s*|import\s*\(|import\s*)['"]([^'"]+)['"]""",s)
def reachable_ts():
    start=[ROOT/'src/main.tsx',ROOT/'src/App.tsx']
    seen=set()
    while start:
        p=start.pop()
        if p in seen or not p.is_file():continue
        seen.add(p)
        for dep in imports_ts(p):
            if not dep.startswith('.'):continue
            base=(p.parent/dep).resolve()
            start += [x for x in [base,*(pathlib.Path(str(base)+ext) for ext in ('.ts','.tsx','.js')),*[base/f'index{ext}' for ext in ('.ts','.tsx')]] if x.exists()]
    return seen
def reachable_python():
    directory=ROOT/'runtime/multipass'
    starts=[directory/'multipass_preview_api.py']
    seen=set()
    while starts:
        p=starts.pop()
        if p in seen or not p.is_file():continue
        seen.add(p)
        try:t=ast.parse(p.read_text())
        except (ValueError,SyntaxError):continue
        for node in ast.walk(t):
            names=[]
            if isinstance(node,ast.Import):names=[a.name.split('.')[0] for a in node.names]
            elif isinstance(node,ast.ImportFrom) and node.module:names=[node.module.split('.')[0]]
            for n in names:
                x=directory/(n+'.py')
                if x.exists():starts.append(x)
    return seen
wt=shell('git','worktree','list','--porcelain')
registered=[pathlib.Path(s.split(' ',1)[1]) for s in wt.splitlines() if s.startswith('worktree ')]
# Include independent study checkouts not attached to the active repo as well.
candidates=sorted({*registered,*(p for p in HOME.glob('parser-studio-*') if p.is_dir())})
relevant_trees=[]
for p in candidates:
    h=safe_git_ref(p)
    if h:relevant_trees.append((p,h))
ui=reachable_ts();py=reachable_python()
historical={}
for feature,(product_files,poc_files) in GRAMMARS.items():
    poc=[]
    for tree,head in relevant_trees:
        matches=[]
        for name in poc_files:
            f=tree/'src'/name
            if f.is_file() and f.resolve()!= (ROOT/'src'/name).resolve():
                matches.append({'file':str(f.relative_to(tree)),'sha256':sha(f)})
        if matches:
            poc.append({'worktree':str(tree),'head':head,'source':matches})
    product=[]
    for name in product_files:
        f=ROOT/'runtime/multipass'/name
        if f.is_file():
            product.append({'path':str(f.relative_to(ROOT)),'reachable':f in py,'sha256':sha(f)})
    for name in poc_files:
        f=ROOT/'src'/name
        if f.is_file():
            product.append({'path':str(f.relative_to(ROOT)),'reachable':f in ui,'sha256':sha(f)})
    historical[feature]={'poc_source_samples':poc,'product_paths':product,
       'static_trace':'STATIC_ONLY_NEEDS_BEHAVIOR_REPLAY','classification':'PENDING_REPLAY',
       'notes':'Filename/symbol presence alone never proves functional equivalence.'}

# Collapse cloned/rebased PoC copies by content hash rather than shipping a
# 500-KB inventory of repeated worktree paths. Source payloads are never read.
for feature,row in historical.items():
    provenance=row.pop('poc_source_samples')
    grouped={}
    for checkout in provenance:
        for ref in checkout['source']:
            key=(ref['file'],ref['sha256'])
            instance=grouped.setdefault(key,{'file':ref['file'],'sha256':ref['sha256'],
                                             'checkout_occurrences':0,'example_checkouts':[]})
            instance['checkout_occurrences']+=1
            if len(instance['example_checkouts'])<3:
                instance['example_checkouts'].append(pathlib.Path(checkout['worktree']).name)
    variants=sorted(grouped.values(),key=lambda item:(-item['checkout_occurrences'],item['file']))
    row['unique_poc_source_variants']=len(variants)
    row['poc_checkout_occurrences']=len(provenance)
    row['poc_source_digest_examples']=variants[:8]
    row['poc_variants_omitted_from_digest_examples']=max(0,len(variants)-8)

# Empirically grounded statuses, separate original source extraction from
# downloadable compiler and actual Stellar DP/native target qualification.
EVIDENCE={
 'syslog_envelope':('SOURCE_EXTRACTED','rfc5424_sd_kv','Existing authored source replay retained the same structural status.'),
 'rfc6587_octet_and_nul':('SOURCE_FRAMED_DRAFT_UNVERIFIED','rfc6587_octet','Two frames recovered by new common container grammar; original transport DRAFT not qualified.'),
 'json_typed_spans':('SOURCE_EXTRACTED','json_single_nested_utf8','Existing typed JSON and UTF-8 source structure unchanged in the corpus replay.'),
 'rfc7464_json_seq':('SOURCE_FRAMED_DRAFT_UNVERIFIED','rfc7464_json_seq','RS/JSON source framing restored; no native wire-compiler claim.'),
 'gelf_tcp':('SOURCE_FRAMED_DRAFT_UNVERIFIED','gelf_tcp','NUL-delimited GELF 1.1 JSON source framing restored; not native-verified.'),
 'ndjson':('SOURCE_EXTRACTED','json_ndjson','Multi-event newline boundaries unchanged.'),
 'cef_grammar':('SOURCE_EXTRACTED','cef_extension','Authored CEF source replay unchanged; independent firmware oracle unavailable.'),
 'leef_grammar':('SOURCE_EXTRACTED','leef_implicit_tab','Authored LEEF source replay unchanged; independent firmware oracle unavailable.'),
 'kv_quotes_duplicates':('SOURCE_PRESERVING_COMPILER_GAP','duplicate_kv','Ordered duplicate key source values retained; downstream mapping not automatically qualified.'),
 'csv_rfc4180':('SOURCE_PARTIAL_DRAFT_GAP','multiline_quoted_csv','Quoted multiline CSV remains conservative PARTIAL and needs native qualification.'),
 'w3c_declared_schema':('SOURCE_EXTRACTED_DRAFT_GAP','w3c_declared_two_rows','Declared original header rows restored; 12/12 pinned publisher claims, native unverified.'),
 'zeek_declared_schema':('SOURCE_EXTRACTED_DRAFT_GAP','zeek_declared_two_rows','Zeek declared original header rows restored; DRAFT parser grammar not qualified.'),
 'journal_export':('SOURCE_GROUPED_DRAFT_GAP','journal_export','Two journal records no longer appear as four independent SOURCE_PARSED KV lines.'),
 'linux_audit_group':('STILL_MISSING_GROUPING','linux_audit_group','Linux audit event sequence group by serial not integrated or independently qualified.'),
 'container_cri_docker':('PARTIAL_CONTAINER_GAP','cri_multiline','CRI partial/final continuation group still absent; Docker JSON line remains source-extracted.'),
 'mixed_format_arbitration':('SOURCE_EXTRACTED_COMPILER_GATED','mixed_json_kv_cef','Mixed source parsing works for authored cases, parser export supports only declared subset.'),
 'utf8_original_spans':('SOURCE_QUALIFIED_NARROW','utf8_bom_kv','All 28 replay cases accounted bytes; pinned W3C lexical/name/decoded values exact.'),
 'relay_prefix_declared':('SOURCE_INSPECTION_ONLY',None,'User-declared prefix/suffix UI inspection is separate from a downloadable wrapping grammar.'),
 'multitype_mapping':('PARTIAL_COMPILER_QUALIFICATION',None,'Threat/user/asset review workflow exists; full dynamic native event mapping not independently qualified.'),
 'stellar_dictionary':('METADATA_ONLY_NOT_NATIVE',None,'Dictionary projection metadata exists, but target field normalization not checked on actual Stellar.'),
 'compiler_status_gating':('IN_PROGRESS_FAIL_CLOSED',None,'Source PARTIAL is not native success; three public beginner review-gate UX gaps reproduced.'),
}
# Inventory key spellings are stable; any missing evidence classification is visible.
for name,row in historical.items():
    state,case,why=EVIDENCE.get(name,('STATIC_ONLY_NEEDS_REPLAY',None,'No same-input behavioral replay available.'))
    row['classification']=state
    row['evidence_case']=case
    row['evidence_note']=why
    row['static_trace']='FILE_AND_IMPORT_REACHABILITY_ONLY_NOT_BEHAVIORAL_PROOF'
out={
 'schema':'parserstudio.poc-product-inventory.v1','date':str(date.today()),
 'baseline_head':shell('git','rev-parse','HEAD'),
 'audit_branch':shell('git','branch','--show-current'),
 'registered_worktree_count':len(registered),
 'available_git_checkout_count':len(relevant_trees),
 'available_git_checkouts':[{'path':str(p),'head':h} for p,h in relevant_trees],
 'reachable_web_module_count':len(ui),
 'reachable_python_module_count':len(py),
 'reachable_web_paths':sorted(str(p.relative_to(ROOT)) for p in ui if p.is_relative_to(ROOT)),
 'reachable_python_paths':sorted(str(p.relative_to(ROOT)) for p in py if p.is_relative_to(ROOT)),
 'features':historical,
 'privacy':'metadata and source code digests only; no private log or fixture payloads',
}
OUT.write_text(json.dumps(out,indent=2,ensure_ascii=True)+'\n')
print(json.dumps({'head':out['baseline_head'],'worktrees':len(registered),
 'checkouts':len(relevant_trees),'features':len(historical),
 'web_reachable':len(ui),'python_reachable':len(py),
 'no_product_counterpart':[name for name,x in historical.items() if not x['product_paths']],
 'output':str(OUT)}))
