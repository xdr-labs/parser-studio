import { createDraft, type MappingRule, type ParserDraft } from '../model';
import { defaultGuidedOptions, type FieldGroup } from './contract';

export const starterTemplateIds = [
  'json', 'kv', 'csv', 'rfc3164_kv', 'syslog_rfc5424', 'rfc5424_cef', 'rfc5424_leef', 'cef', 'leef', 'mixed', 'mixed_rfc5424', 'mixed_rfc3164', 'mixed_rfc5424_bodies',
] as const;
export type StarterTemplateId = (typeof starterTemplateIds)[number];

export interface StarterTemplate {
  id: StarterTemplateId;
  label: string;
  description: string;
  sample: string;
  draft: ParserDraft;
}

const presets: Record<StarterTemplateId, { label: string; description: string; samples: string[] }> = {
  json: {
    label: 'JSON · Firewall',
    description: 'One JSON object per line',
    samples: [
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"203.0.113.11","dst_port":22}',
    ],
  },
  kv: {
    label: 'Key / Value · Firewall',
    description: 'Whitespace-delimited key=value',
    samples: [
      'action=allow src_ip=198.51.100.10 dst_port=443',
      'action=deny src_ip=203.0.113.11 dst_port=22',
    ],
  },
  csv: {
    label: 'CSV · Firewall',
    description: 'Comma-separated action,src_ip,dst_port',
    samples: [
      'allow,198.51.100.10,443',
      'deny,203.0.113.11,22',
    ],
  },
  rfc3164_kv: {
    label: 'RFC3164 + KV · Security Event',
    description: 'Strict yearless RFC3164 TAG: message carrying key=value fields',
    samples: [
      '<34>Oct  9 14:15:16 demo-fw security[122]: src_ip=198.51.100.10 dst_port=443 action=allow',
      '<34>Oct  9 14:15:17 demo-fw security[122]: src_ip=203.0.113.11 dst_port=22 action=deny',
    ],
  },
  syslog_rfc5424: {
    label: 'RFC5424 · System Log',
    description: 'Strict RFC5424 header with plain-text body',
    samples: [
      '<34>1 2026-10-12T00:00:00Z demo-fw network 12 EVT01 - allow connection',
      '<34>1 2026-10-12T00:00:01Z demo-fw network 12 EVT02 - deny connection',
    ],
  },
  rfc5424_cef: {
    label: 'RFC5424 + CEF · Security Event',
    description: 'RFC5424 v1 header with CEF:0 body and supported adjacent structured data',
    samples: [
      '<165>1 2026-10-12T00:00:00Z demo-fw security 12 EV01 [origin@32473 site="demo"][trace@32473 id="1"] CEF:0|Example|Firewall|1|100|Allowed|5|act=allow src=198.51.100.10 dpt=443',
      '<165>1 2026-10-12T00:00:01Z demo-fw security 12 EV02 - CEF:0|Example|Firewall|1|101|Denied|8|act=deny src=203.0.113.11 dpt=22',
    ],
  },
  rfc5424_leef: {
    label: 'RFC5424 + LEEF · Security Event',
    description: 'RFC5424 v1 header with a LEEF 2.0 hex-delimited body',
    samples: [
      '<165>1 2026-10-12T00:00:00Z demo-fw security 12 EV01 - LEEF:2.0|Example|Firewall|1|100|0x5E|act=allow^src=198.51.100.10^dstPort=443',
      '<165>1 2026-10-12T00:00:01Z demo-fw security 12 EV02 - LEEF:2.0|Example|Firewall|1|101|0x5E|act=deny^src=203.0.113.11^dstPort=22',
    ],
  },
  cef: {
    label: 'CEF · Security Event',
    description: 'Standalone CEF record without a Syslog prefix',
    samples: [
      'CEF:0|Example|Firewall|1|100|Allowed|5|action=allow src_ip=198.51.100.10 dst_port=443',
      'CEF:0|Example|Firewall|1|101|Denied|8|action=deny src_ip=203.0.113.11 dst_port=22',
    ],
  },
  mixed_rfc5424_bodies:{
    label:'Mixed JSON/KV + RFC5424 JSON/KV · Firewall',
    description:'One explicitly reviewed listener for standalone and RFC5424-wrapped JSON and KV',
    samples:[
      '{"src_ip":"192.0.2.10","action":"deny"}',
      'src_ip=198.51.100.8 action=allow',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - {"src_ip":"192.0.2.19","action":"deny"}',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - src_ip=203.0.113.4 action=allow',
    ],
  },
  mixed_rfc3164:{
    label:'Mixed JSON + KV + RFC3164 TAG KV · Firewall',
    description:'Strict yearless RFC3164 TAG: and standalone JSON/KV on one chosen Syslog port',
    samples:[
      '{"src_ip":"192.0.2.10","action":"deny"}',
      'src_ip=198.51.100.8 action=allow',
      '<34>Oct  9 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
    ],
  },
  mixed_rfc5424:{
    label:'Mixed JSON + RFC5424 CEF/LEEF · Security',
    description:'One explicitly reviewed parser port for standalone JSON and wrapped CEF/LEEF',
    samples:[
      '{"src_ip":"192.0.2.10","dst_port":443,"action":"deny"}',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow',
    ],
  },
  mixed: {
    label:'Mixed JSON + KV + CEF + LEEF · Security',
    description:'Explicit four-family single-line dispatcher; no generic fallback',
    samples:[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      'src_ip=203.0.113.11 dst_port=22 action=deny',
      'CEF:0|Synthetic|Firewall|1|101|Denied|8|src=192.0.2.11 dpt=443 act=deny',
      'LEEF:1.0|Synthetic|Firewall|1|501|src=192.0.2.18\tdstPort=80\tact=allow',
    ],
  },
  leef: {
    label: 'LEEF · Security Event',
    description: 'LEEF 1.0 with tab-delimited fields',
    samples: [
      'LEEF:1.0|Example|Firewall|1|100|action=allow\tsrc_ip=198.51.100.10\tdst_port=443',
      'LEEF:1.0|Example|Firewall|1|101|action=deny\tsrc_ip=203.0.113.11\tdst_port=22',
    ],
  },
};

export function starterTemplateInfo(id: StarterTemplateId): Pick<StarterTemplate, 'id' | 'label' | 'description'> {
  return { id, label: presets[id].label, description: presets[id].description };
}

/** Explicit opt-in starter, always fresh. All addresses are RFC 5737 documentation-only samples. */
export function loadStarterTemplate(id: StarterTemplateId): StarterTemplate {
  const spec = presets[id];
  const draft = createDraft();
  draft.name = 'Synthetic ' + spec.label;
  draft.vendor = 'Synthetic demo (no customer data)';
  draft.format = id === 'rfc5424_cef' || id === 'rfc5424_leef'
    ? 'syslog_rfc5424' : id==='rfc3164_kv'?'syslog_rfc3164':(id==='mixed_rfc5424'||id==='mixed_rfc3164'||id==='mixed_rfc5424_bodies')?'mixed':id;
  draft.csvColumns = 'action,src_ip,dst_port';
  const guided = defaultGuidedOptions();
  guided.slug = 'example_' + id;
  guided.eventBoundary = 'single-line';
  guided.enrichment = [];

  if(id==='mixed_rfc5424_bodies'){
    draft.mixedFormats=['json','kv','rfc5424_json','rfc5424_kv'];
    draft.mappings=[
      {id:'plain-ip',source:'src_ip',target:'custom.source_ip',type:'ip'},
      {id:'plain-action',source:'action',target:'custom.action',type:'string'},
      {id:'wrapped-ip',source:'body.src_ip',target:'custom.wrapped_ip',type:'ip'},
      {id:'wrapped-action',source:'body.action',target:'custom.wrapped_action',type:'string'},
      {id:'event-time',source:'syslog_timestamp',target:'custom.timestamp',type:'timestamp'},
    ];
    guided.groups={
      'plain-ip':'top_fields','plain-action':'top_fields',
      'wrapped-ip':'ns_fields','wrapped-action':'top_fields','event-time':'vendor_fields',
    };
    guided.classification={defaultIndex:'Syslog',rules:[
      {id:'deny-plain',sourceField:'action',equals:'deny',index:'Threat'},
      {id:'deny-wrapped',sourceField:'body.action',equals:'deny',index:'Threat'},
    ]};
  }
  if(id==='mixed_rfc3164'){
    draft.mixedFormats=['json','kv','rfc3164_kv'];
    draft.mappings=[
      {id:'standalone-ip',source:'src_ip',target:'custom.source_ip',type:'ip'},
      {id:'standalone-action',source:'action',target:'custom.action',type:'string'},
      {id:'wrapped-ip',source:'body.src_ip',target:'custom.wrapped_ip',type:'ip'},
      {id:'wrapped-action',source:'body.action',target:'custom.wrapped_action',type:'string'},
      {id:'unknown-year',source:'syslog_time_policy',target:'custom.year_zone_policy',type:'string'},
    ];
    guided.groups={
      'standalone-ip':'top_fields','standalone-action':'top_fields',
      'wrapped-ip':'ns_fields','wrapped-action':'top_fields',
      'unknown-year':'vendor_fields',
    };
    guided.classification={
      defaultIndex:'Syslog',rules:[
        {id:'deny-standalone',sourceField:'action',equals:'deny',index:'Threat'},
        {id:'deny-rfc3164',sourceField:'body.action',equals:'deny',index:'Threat'},
      ],
    };
  }
  if(id==='mixed_rfc5424'){
    draft.mixedFormats=['json','rfc5424_cef','rfc5424_leef'];
    draft.mappings=[
      {id:'plain-ip',source:'src_ip',target:'custom.plain_source_ip',type:'ip'},
      {id:'plain-port',source:'dst_port',target:'custom.plain_destination_port',type:'port'},
      {id:'plain-action',source:'action',target:'custom.plain_action',type:'string'},
      {id:'wrapped-ip',source:'body.src',target:'custom.wrapped_source_ip',type:'ip'},
      {id:'wrapped-cef-port',source:'body.dpt',target:'custom.wrapped_cef_port',type:'port'},
      {id:'wrapped-leef-port',source:'body.dstPort',target:'custom.wrapped_leef_port',type:'port'},
      {id:'wrapped-action',source:'body.act',target:'custom.wrapped_action',type:'string'},
    ];
    guided.groups={
      'plain-ip':'top_fields','plain-port':'ns_fields','plain-action':'top_fields',
      'wrapped-ip':'top_fields','wrapped-cef-port':'ns_fields',
      'wrapped-leef-port':'ns_fields','wrapped-action':'top_fields',
    };
    guided.classification={
      defaultIndex:'Syslog',rules:[
        {id:'json-deny',sourceField:'action',equals:'deny',index:'Threat'},
        {id:'wrapped-deny',sourceField:'body.act',equals:'deny',index:'Threat'},
      ],
    };
  }
  if(id==='mixed'){
    draft.mixedFormats=['json','kv','cef','leef'];
    draft.mappings=[
      {id:'source-ip',source:'src_ip',target:'custom.source_ip',type:'ip'},
      {id:'target-port',source:'dst_port',target:'custom.destination_port',type:'port'},
      {id:'action',source:'action',target:'custom.action',type:'string'},
      {id:'mixed-source',source:'src',target:'custom.mixed_source_ip',type:'ip'},
      {id:'mixed-port-cef',source:'dpt',target:'custom.mixed_cef_port',type:'port'},
      {id:'mixed-port-leef',source:'dstPort',target:'custom.mixed_leef_port',type:'port'},
      {id:'mixed-action',source:'act',target:'custom.mixed_action',type:'string'},
    ];
    guided.groups={
      'source-ip':'top_fields','target-port':'ns_fields',
      action:'top_fields','mixed-source':'top_fields',
      'mixed-port-cef':'ns_fields','mixed-port-leef':'ns_fields',
      'mixed-action':'top_fields',
    };
    guided.classification.rules=[
      {id:'deny',sourceField:'action',equals:'deny',index:'Threat'},
      {id:'deny-cef',sourceField:'act',equals:'deny',index:'Threat'},
    ];
  }
  if(id==='rfc3164_kv'){
    draft.syslogBodyFormat='kv';
    draft.mappings=[
      {id:'source-ip',source:'body.src_ip',target:'custom.source_ip',type:'ip'},
      {id:'target-port',source:'body.dst_port',target:'custom.destination_port',type:'port'},
      {id:'action',source:'body.action',target:'custom.action',type:'string'},
      {id:'time-policy',source:'syslog_time_policy',target:'custom.timestamp_policy',type:'string'},
    ];
    guided.groups={'source-ip':'top_fields','target-port':'ns_fields',
      action:'top_fields','time-policy':'vendor_fields'};
    guided.classification.rules=guided.classification.rules.map(rule=>({
      ...rule,sourceField:'body.action',
    }));
  }

  if (id === 'rfc5424_cef' || id === 'rfc5424_leef') {
    const isCef = id === 'rfc5424_cef';
    draft.syslogBodyFormat = isCef ? 'cef' : 'leef';
    const portSource = isCef ? 'body.dpt' : 'body.dstPort';
    draft.mappings = [
      { id: 'source-ip', source: 'body.src', target: 'custom.source_ip', type: 'ip' },
      { id: 'target-port', source: portSource, target: 'custom.destination_port', type: 'port' },
      { id: 'action', source: 'body.act', target: 'custom.action', type: 'string' },
    ];
    guided.groups = {
      'source-ip': 'top_fields', 'target-port': 'ns_fields', action: 'top_fields',
    };
    guided.classification.rules = guided.classification.rules.map(rule => ({
      ...rule, sourceField: 'body.act',
    }));
  }

  if (id === 'syslog_rfc5424') {
    const rfcMappings: MappingRule[] = [
      { id: 'rfc-host', source: 'syslog_hostname', target: 'custom.device', type: 'string' },
      { id: 'rfc-pri', source: 'syslog_pri', target: 'custom.priority', type: 'integer' },
      { id: 'rfc-msg', source: 'message', target: 'custom.message', type: 'string' },
      { id: 'rfc-time', source: 'syslog_timestamp', target: 'custom.timestamp', type: 'timestamp' },
    ];
    draft.mappings = rfcMappings;
    guided.groups = Object.fromEntries(rfcMappings.map((rule) => [rule.id, 'top_fields' as FieldGroup]));
    guided.classification = { defaultIndex: 'Syslog', rules: [] };
  }
  draft.guided = guided;
  return { id, label: spec.label, description: spec.description, sample: spec.samples.join('\n'), draft };
}
