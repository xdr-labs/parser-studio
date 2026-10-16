import type {ParserDraft,SuiteResult} from '../model';
import {MAX_EVENTS,splitEvents} from '../parser';
import {defaultGuidedOptions} from './contract';
import {buildReviewableRecipe} from './parserRecipeV2';
import {sha256Utf8Hex} from '../sha256';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

export interface BeginnerRepairContext {
  fullSource:string;
  eventSource:string;
  preview:MultiPassSourcePreview;
  draft?:ParserDraft;
  suite?:SuiteResult;
  recommendation:{label:string;text:string};
}
function utf8Slice(source:string,startByte:number,endByte:number):string{
  const data=new TextEncoder().encode(source);
  try{return new TextDecoder('utf-8',{fatal:true}).decode(data.slice(startByte,endByte));}
  catch{return '';}
}
export async function buildBeginnerRepairPrompt(ctx:BeginnerRepairContext):Promise<string>{
  const {fullSource,eventSource,preview,draft,suite,recommendation}=ctx;
  const lines=[
    'Parser Studio — security log parser repair request.',
    '',
    'Detected syntax: '+preview.syntax,
    'Current extraction status: '+preview.status,
    'Recommended repair method: '+recommendation.label,
    recommendation.text,
    '',
    'Original problem event:',
    'BEGIN PROBLEM EVENT',
    eventSource,
    'END PROBLEM EVENT',
    '',
    'Fields already extracted successfully:',
    ...(Object.keys(preview.fields).length?Object.keys(preview.fields).map(x=>'- '+x):['- none']),
    '',
    'Parser issues:',
    ...(preview.issues.length?preview.issues.map(x=>'- '+x):['- no explicit issue code']),
  ];
  if(preview.residuals.length){
    lines.push('', 'Unparsed source regions:');
    for(const [index,region] of preview.residuals.entries()){
      lines.push(`Region ${index+1} · UTF-8 bytes ${region.startByte}-${region.endByte}`,
        'BEGIN UNPARSED REGION',utf8Slice(eventSource,region.startByte,region.endByte),'END UNPARSED REGION');
    }
  }else{
    lines.push('', 'No trustworthy smaller residual range is available; review the whole problem event.');
  }

  lines.push('',
    'ParserRecipe safety contract:',
    'Use only Parser Studio declarative stages: JSON/KV/CEF/LEEF/CSV, supported Syslog wrappers, reviewed parse_generic_structural only when the local backend advertises GENERIC_STRUCTURAL_ULTRA_COMPILER_V14 and the event matches that bounded grammar, bounded split/merge, or bounded parse_regex for otherwise unresolved one-line text.',
    'For parse_regex: pattern must be at most 256 visible characters, contain one or more unique named captures (?<field>...), and must not use backreferences, lookbehind, unsafe nested repetition or excessive repetition bounds.',
    'Grok, JSONata execution, scripting and executable Ruby are not ParserRecipe stages.',
    'For JSON, prefer direct field paths. If reshaping is needed, prefer supported declarative split/merge rather than inventing executable JSONata.');

  if(draft&&suite){
    const baseline=await buildReviewableRecipe(fullSource,draft,suite);
    if(baseline.ok){
      lines.push('',
        'Current canonical ParserRecipe v0.2:',
        'Preserve every unrelated stage and mapping. Change only what is required to repair the unresolved source.',
        'BEGIN CURRENT PARSER RECIPE',
        JSON.stringify(baseline.recipe,null,2),
        'END CURRENT PARSER RECIPE');
    }else{
      const opts=draft.guided??defaultGuidedOptions();
      const boundary=draft.guided?.eventBoundary??'single-line';
      const records=splitEvents(fullSource,boundary,MAX_EVENTS+1);
      lines.push('',
        'No compiler-ready baseline recipe exists.',
        `Recovery identity: projectId=draft-${opts.slug}`,
        `sourceSha256=${await sha256Utf8Hex(fullSource)}`,
        `events=${records.length}`);
    }
  }

  const metadataReview=recommendation.label==='Review source metadata';
  lines.push('','Required output:');
  if(metadataReview){
    lines.push(
      '- Return one JSON object with contract "parser-studio.source-metadata-review.v0.1".',
      '- Explain the source timestamp/structured-data anomaly and whether it should be corrected upstream or intentionally preserved.',
      '- Do not propose a Regex merely to hide malformed source metadata.');
  }else{
    lines.push(
      '- Return only one ParserRecipe v0.2 JSON object using supported declarative stages.',
      '- For FULL_RECOVERY, preserve every already-extracted source value occurrence in the final parser output. A reviewed lossless source projection such as Generic Structural parserstudio_source may provide that preservation; otherwise use explicit map_field stages. Do not leave successfully extracted values only in an intermediate extraction object.',
      ...(preview.residuals.length?['- For FULL_RECOVERY, preserve every unparsed source region listed above in the final parser output too. Capturing a region as raw_event is not enough unless that capture is mapped into final output (or retained by an approved lossless source projection).']:[]),
      '- Prefer parse_generic_structural over a broad Regex only when the problem event matches the reviewed Generic Structural compiler grammar advertised by the local backend.',
      '- For an unresolved text body, parse_regex is allowed only under the bounded named-capture rules stated above.',
      '- Parser Studio will run independent holdout validation before any rule can be applied.');
  }
  lines.push(
    '- Preserve already-correct extraction and unrelated mappings.',
    '- Do not drop unmatched events.',
    '- Do not infer values that are not present in the source.',
    '- Do not claim native Fluentd or Stellar target verification.');
  return lines.join('\n');
}