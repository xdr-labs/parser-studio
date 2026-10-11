import { createDraft, type MappingRule, type ParserDraft } from '../model';
import { defaultGuidedOptions, type FieldGroup } from './contract';

export const starterTemplateIds = [
  'json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef',
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
    label: 'JSON · 방화벽',
    description: '한 줄에 하나의 JSON 객체',
    samples: [
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"203.0.113.11","dst_port":22}',
    ],
  },
  kv: {
    label: 'Key / Value · 방화벽',
    description: '공백으로 구분된 key=value',
    samples: [
      'action=allow src_ip=198.51.100.10 dst_port=443',
      'action=deny src_ip=203.0.113.11 dst_port=22',
    ],
  },
  csv: {
    label: 'CSV · 방화벽',
    description: '쉼표로 분리된 action,src_ip,dst_port',
    samples: [
      'allow,198.51.100.10,443',
      'deny,203.0.113.11,22',
    ],
  },
  syslog_rfc5424: {
    label: 'RFC5424 · 시스템 로그',
    description: '정확한 RFC5424 헤더와 일반 텍스트 본문',
    samples: [
      '<34>1 2026-10-12T00:00:00Z demo-fw network 12 EVT01 - allow connection',
      '<34>1 2026-10-12T00:00:01Z demo-fw network 12 EVT02 - deny connection',
    ],
  },
  cef: {
    label: 'CEF · 보안 이벤트',
    description: 'Syslog 접두부 없는 독립 CEF 레코드',
    samples: [
      'CEF:0|Example|Firewall|1|100|Allowed|5|action=allow src_ip=198.51.100.10 dst_port=443',
      'CEF:0|Example|Firewall|1|101|Denied|8|action=deny src_ip=203.0.113.11 dst_port=22',
    ],
  },
  leef: {
    label: 'LEEF · 보안 이벤트',
    description: 'LEEF 1.0의 TAB 구분 필드',
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
  draft.format = id;
  draft.csvColumns = 'action,src_ip,dst_port';
  const guided = defaultGuidedOptions();
  guided.slug = 'example_' + id;
  guided.eventBoundary = 'single-line';
  guided.enrichment = [];

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
