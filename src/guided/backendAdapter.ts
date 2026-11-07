import {supportsCanonicalClassificationOperator} from '../../backend/src/canonical-operator-contract';
import type { ParserDraft } from '../model';
import {validMappingWhen} from '../fieldPaths';
import {isGenericStructuralProfile,type GenericStructuralProfile} from '../genericStructuralProfiles';
import {validateEventProfiles} from './multiEventRouting';
import {validForwarderConfig} from './declaredForwarder';
import {
  compilerDraftContract, defaultGuidedOptions,
  type EventClass, type FieldGroup, type SourceCategory,
} from './contract';

export type BackendLogIndex = 'session' | 'threat' | 'syslog' | 'winlogevent';
export type BackendFieldType = 'string' | 'integer' | 'ip' | 'port' | 'boolean' | 'date';

export interface BackendField {
  normalized_name: string;
  data_type: BackendFieldType;
  source_path_kind?: 'literal_root' | 'nested';
  when?:{sourcePath:string;operator:'in';values:string[]};
  time_format?: 'iso8601';
  timezone?: 'UTC';
}

export type BackendEnrichmentRule =
  | { operator: 'set_const'; target: string; value: string }
  | { operator: 'copy' | 'lowercase' | 'uppercase'; source: string; target: string }
  | { operator: 'split_field'; source: string; delimiter: string; targets: string[] }
  | { operator: 'merge_fields'; sources: string[]; delimiter: string; target: string };

export interface BackendParserProject {
  schemaRevision: '0.1';
  projectId: string;
  revision: 1;
  slug: string;
  vendor: string;
  product: string;
  productVersion?: string;
  sourceCategory: SourceCategory;
  receiver: {
    protocols: ('udp' | 'tcp')[];
    port: number;
    bindAddress: '127.0.0.1' | '0.0.0.0';
    messageLengthLimit: number;
    tcpFraming: 'line' | 'blank_line_json' | 'blank_line_java';
  };
  extraction: ({ format: 'json' | 'kv' | 'cef' | 'leef' | 'java_stacktrace' | 'generic_structural' } | {format:'regex';pattern:string} | { format: 'mixed'; mixedFormats: Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>;csvColumns?:string[];csvDelimiter?:','|';'|'\t' } | { format: 'syslog_rfc3164' | 'syslog_rfc5424'; syslogBodyFormat?: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex';pattern?:string } | { format: 'csv'; csvColumns: string[]; csvDelimiter: ',' | ';' | '\t' }) & {forwarder?:{maxHops:1|2|3;relayHosts:string[]};genericStructuralProfile?:GenericStructuralProfile;omitSourceRaw?:true};
  normalization: {
    msgOriginSource: string;
    msgClass: string;
    msgOriginCategory: string;
    ignoreValues: string[];
    topFields: Record<string, BackendField>;
    nsFields: Record<string, BackendField>;
    vendorFields: Record<string, BackendField>;
    eventProfiles?:{
      discriminator:string;unknown:'reject';
      variants:Array<{
        name:string;equals:string;
        topFields:Record<string,BackendField>;
        nsFields:Record<string,BackendField>;
        vendorFields:Record<string,BackendField>;
      }>;
    };
  };
  enrichment?: BackendEnrichmentRule[];
  classification: {
    defaultIndex: BackendLogIndex;
    rules: { field: string; operator: 'equals'; value: string; index: BackendLogIndex }[];
  };
}

export interface AdapterIssue {
  code: string;
  path: string;
  message: string;
}
export type BackendProjectResult =
  | { ok: true; project: BackendParserProject; issues: [] }
  | { ok: false; issues: AdapterIssue[] };

const indexMap: Record<EventClass, BackendLogIndex> = {
  Session: 'session', Threat: 'threat', Syslog: 'syslog', Winlogevent: 'winlogevent',
};

const UNSAFE_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const SOURCE_CATEGORIES: SourceCategory[] = ['network', 'endpoint', 'cloud', 'application', 'other'];

function safeFieldPath(path: string): boolean {
  return path.split('.').every((part) => part && !UNSAFE_SEGMENTS.has(part));
}

/**
 * Explicit UI -> backend contract adapter for PR #4's ParserProject 0.1.
 * It never receives raw sample text; rejects all lossy/ambiguous conversions.
 */
export function toBackendProject(draft: ParserDraft): BackendProjectResult {
  const local = compilerDraftContract(draft);
  if (!local.ok) {
    return {
      ok: false,
      issues: local.errors.map((message, index) => ({
        code: 'UI_VALIDATION',
        path: '/draft/' + index,
        message,
      })),
    };
  }
  const options = draft.guided ?? defaultGuidedOptions();
  const issues: AdapterIssue[] = [];
  if(draft.genericStructuralProfile!==undefined&&
    (!isGenericStructuralProfile(draft.genericStructuralProfile)||draft.format!=='generic_structural'))
    issues.push({code:'GENERIC_STRUCTURAL_PROFILE',path:'/genericStructuralProfile',
      message:'The additional Generic Structural profile requires its supported extraction format.'});
  if(draft.omitSourceRaw!==undefined&&
    (draft.omitSourceRaw!==true||draft.format!=='generic_structural'))
    issues.push({code:'OMIT_SOURCE_RAW',path:'/omitSourceRaw',
      message:'Leaving out the raw line is only available for Generic Structural.'});
  const topFields: Record<string, BackendField> = Object.create(null);
  const nsFields: Record<string, BackendField> = Object.create(null);
  const vendorFields: Record<string, BackendField> = Object.create(null);
  const fieldsByGroup: Record<FieldGroup, Record<string, BackendField>> = {
    top_fields: topFields, ns_fields: nsFields, vendor_fields: vendorFields,
  };
  const destinationForSource = new Map<string, string>();
  for (const [index, mapping] of draft.mappings.entries()) {
    if(mapping.when!==undefined&&!validMappingWhen(mapping.when)){
      issues.push({code:'INVALID_MAPPING_WHEN',path:'/mappings/'+index,
        message:'Only bounded exact-value mapping predicates are supported.'});
      continue;
    }
    const group = options.groups[mapping.id] ?? 'vendor_fields';
    if (!safeFieldPath(mapping.source) || !safeFieldPath(mapping.target)) {
      issues.push({ code: 'UNSAFE_FIELD', path: '/mappings/' + index, message: 'Prototype/constructor field paths are not allowed' });
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(fieldsByGroup, group)) {
      issues.push({ code: 'INVALID_GROUP', path: '/mappings/' + index, message: 'Unknown target field group' });
      continue;
    }
    const collection = fieldsByGroup[group];
    if (Object.prototype.hasOwnProperty.call(collection, mapping.source)) {
      issues.push({ code: 'DUPLICATE_SOURCE', path: '/mappings/' + index, message: 'This source is already mapped in the same output group: ' + mapping.source });
      continue;
    }
    const data_type: BackendFieldType = mapping.type === 'timestamp' ? 'date' : mapping.type as BackendFieldType;
    collection[mapping.source] = {
      normalized_name: mapping.target,
      data_type,
      ...(mapping.sourcePathKind?{source_path_kind:mapping.sourcePathKind}:{}),
      ...(mapping.when?{when:mapping.when}:{}),
      ...(data_type === 'date' ? { time_format: 'iso8601' as const, timezone: 'UTC' as const } : {}),
    };
    // Backend classification is evaluated after normalization and currently
    // reads only top/namespace fields; vendor names need explicit remapping.
    if (group !== 'vendor_fields') destinationForSource.set(mapping.source, mapping.target);
  }
  const rules: BackendParserProject['classification']['rules'] = [];
  for (const [index, rule] of options.classification.rules.entries()) {
    const normalized = destinationForSource.get(rule.sourceField);
    if (!normalized) {
      issues.push({
        code: 'CLASSIFICATION_SOURCE_NOT_AVAILABLE',
        path: '/classification/rules/' + index,
        message: 'Classification rule ' + (index + 1) + ': ' + rule.sourceField + ' must map to Common or Network Fields to support classification on this backend.',
      });
      continue;
    }
    const mapping=draft.mappings.find(candidate=>candidate.source===rule.sourceField&&
      (options.groups[candidate.id]??'vendor_fields')!=='vendor_fields');
    if(!supportsCanonicalClassificationOperator('equals',mapping?.type)){
      issues.push({code:'CLASSIFICATION_NONSTRING_FIELD',path:'/classification/rules/'+index,
        message:'String equals classification requires a reviewed text mapping. Numeric and boolean fields cannot be compared to text in generated Ruby.'});
      continue;
    }
    rules.push({ field: normalized, operator: 'equals', value: rule.equals, index: indexMap[rule.index] });
  }
  const category = options.sourceCategory ?? 'network';
  if (!SOURCE_CATEGORIES.includes(category)) {
    issues.push({ code: 'SOURCE_CATEGORY_UNSUPPORTED', path: '/sourceCategory', message: 'Unknown source category' });
  }
  // Explicit, reviewed family mappings are preserved through this adapter.
  // Never convert an unknown source event into a global default mapping.
  let eventProfiles:BackendParserProject['normalization']['eventProfiles'];
  if(draft.eventProfiles){
    const problem=validateEventProfiles(draft.eventProfiles);
    if(problem)issues.push({code:'INVALID_EVENT_PROFILES',path:'/eventProfiles',message:problem});
    else{
      const variants:NonNullable<typeof eventProfiles>['variants']=[];
      for(const variant of draft.eventProfiles.variants){
        const topFields:Record<string,BackendField>=Object.create(null);
        const nsFields:Record<string,BackendField>=Object.create(null);
        const vendorFields:Record<string,BackendField>=Object.create(null);
        const buckets={top_fields:topFields,ns_fields:nsFields,vendor_fields:vendorFields};
        for(const [index,mapping] of variant.mappings.entries()){
          if(mapping.when!==undefined&&!validMappingWhen(mapping.when)){
            issues.push({code:'INVALID_EVENT_MAPPING_WHEN',
              path:'/eventProfiles/'+variant.name+'/'+index,
              message:'Unsupported event-specific mapping predicate.'});
            continue;
          }
          const group=options.groups[mapping.id]??'vendor_fields';
          if(!safeFieldPath(mapping.source)||!safeFieldPath(mapping.target)||
             !Object.prototype.hasOwnProperty.call(buckets,group)||
             mapping.type==='number'){
            issues.push({code:'INVALID_EVENT_MAPPING',
              path:'/eventProfiles/'+variant.name+'/'+index,
              message:'Event-specific mapping requires reviewed safe paths and types.'});
            continue;
          }
          const bucket=buckets[group];
          if(Object.prototype.hasOwnProperty.call(bucket,mapping.source)){
            issues.push({code:'DUPLICATE_EVENT_SOURCE',
              path:'/eventProfiles/'+variant.name+'/'+index,
              message:'Duplicate source field in one event family.'});
            continue;
          }
          const data_type:BackendFieldType=mapping.type==='timestamp'?'date':
            mapping.type as BackendFieldType;
          bucket[mapping.source]={
            normalized_name:mapping.target,data_type,
            ...(mapping.sourcePathKind?{source_path_kind:mapping.sourcePathKind}:{}),
            ...(mapping.when?{when:mapping.when}:{}),
            ...(data_type==='date'?{time_format:'iso8601' as const,timezone:'UTC' as const}:{}),
          };
        }
        variants.push({name:variant.name,equals:variant.equals,topFields,nsFields,vendorFields});
      }
      eventProfiles={discriminator:draft.eventProfiles.discriminator,
        unknown:'reject',variants};
    }
  }
  // Mirror the backend destination-overlap rule before the user can apply a
  // reviewed draft. Different variants may reuse an output; shared and local
  // outputs (including parent/child dotted paths) may not overlap in a variant.
  if(eventProfiles){
    const commonOutputs=[
      ...Object.values(topFields).map(x=>x.normalized_name),
      ...Object.values(nsFields).map(x=>x.normalized_name),
      ...Object.values(vendorFields).map(x=>draft.vendor+'.'+x.normalized_name),
    ];
    for(const variant of eventProfiles.variants){
      const seen=[...commonOutputs];
      const outputGroups=[
        ...Object.values(variant.topFields).map(x=>x.normalized_name),
        ...Object.values(variant.nsFields).map(x=>x.normalized_name),
        ...Object.values(variant.vendorFields).map(x=>draft.vendor+'.'+x.normalized_name),
      ];
      for(const output of outputGroups){
        if(seen.some(other=>other===output||other.startsWith(output+'.')||
          output.startsWith(other+'.'))){
          issues.push({code:'EVENT_OUTPUT_COLLISION',
            path:'/eventProfiles/'+variant.name,
            message:'An event-specific output overlaps a shared or another event-specific mapping. Review the destination field names.'});
        }
        seen.push(output);
      }
    }
  }
  if(draft.forwarder&&!validForwarderConfig(draft.forwarder))
    issues.push({code:'INVALID_FORWARDER_PROFILE',path:'/forwarder',
      message:'Declare valid distinct relay hosts and 1–3 hops.'});
  if(draft.forwarder&&!['json','kv','cef','leef','mixed',
    'syslog_rfc3164','syslog_rfc5424'].includes(draft.format))
    issues.push({code:'FORWARDER_FORMAT_UNSUPPORTED',path:'/forwarder',
      message:'The selected format does not support declared relays.'});
  if (issues.length) return { ok: false, issues };
  const project: BackendParserProject = {
    schemaRevision: '0.1',
    projectId: 'draft-' + options.slug,
    revision: 1,
    slug: options.slug,
    vendor: draft.vendor,
    product: draft.name,
    ...(draft.version?.trim()?{productVersion:draft.version.trim()}:{}),
    sourceCategory: category,
    receiver: {
      protocols: options.receiver.protocols,
      port: options.receiver.port,
      bindAddress: options.receiver.bindPolicy === 'all' ? '0.0.0.0' : '127.0.0.1',
      messageLengthLimit: options.receiver.messageLimit,
      tcpFraming: options.receiver.framing==='blank_line_json'?'blank_line_json':options.receiver.framing==='blank_line_java'?'blank_line_java':'line',
    },
    extraction: draft.format === 'mixed'
      ? {format:'mixed',mixedFormats:[...(draft.mixedFormats??[])],
          ...((draft.mixedFormats??[]).includes('csv')?{
            csvColumns:draft.csvColumns.split(',').map(x=>x.trim()),
            csvDelimiter:draft.csvDelimiter??',',
          }:{})}
      : draft.format === 'csv'
      ? { format: 'csv', csvColumns: draft.csvColumns.split(',').map((column) => column.trim()), csvDelimiter: draft.csvDelimiter ?? ',' }
      : draft.format === 'regex'
        ? {format:'regex',pattern:draft.pattern}
      : (draft.format === 'syslog_rfc3164'||draft.format==='syslog_rfc5424')
        ? { format: draft.format,
            ...(draft.syslogBodyFormat && draft.syslogBodyFormat !== 'raw'
              ? { syslogBodyFormat: draft.syslogBodyFormat } : {}),
            ...(draft.syslogBodyFormat==='regex'?{pattern:draft.pattern}:{}) }
        : { format: draft.format as 'json' | 'kv' | 'cef' | 'leef' | 'java_stacktrace' | 'generic_structural',
            ...(draft.genericStructuralProfile?{genericStructuralProfile:draft.genericStructuralProfile}:{}),
            ...(draft.omitSourceRaw===true&&draft.format==='generic_structural'?{omitSourceRaw:true as const}:{}) },
    normalization: {
      ...(eventProfiles?{eventProfiles}:{}),
      msgOriginSource: options.slug,
      msgClass: options.slug,
      msgOriginCategory: category,
      ignoreValues: ['', 'N/A', '-'],
      topFields, nsFields, vendorFields,
    },
    ...(options.enrichment?.length ? {
      enrichment: options.enrichment.map((rule): BackendEnrichmentRule => {
        if(rule.operator==='set_const')return {operator:'set_const',target:rule.target,value:rule.value};
        if(rule.operator==='split_field')return {operator:'split_field',source:rule.source,
          delimiter:rule.delimiter!,targets:[...(rule.targets??[])]};
        if(rule.operator==='merge_fields')return {operator:'merge_fields',sources:[...(rule.sources??[])],
          delimiter:rule.delimiter!,target:rule.target};
        return {operator:rule.operator,source:rule.source,target:rule.target};
      }),
    } : {}),
    classification: {
      defaultIndex: indexMap[options.classification.defaultIndex],
      rules,
    },
  };
  if(draft.forwarder)project.extraction={
    ...project.extraction,forwarder:{
      maxHops:draft.forwarder.maxHops,
      relayHosts:[...draft.forwarder.relayHosts],
    },
  };
  return { ok: true, project, issues: [] };
}
