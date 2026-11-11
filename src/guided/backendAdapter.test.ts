import { describe, expect, it } from 'vitest';
import { createDraft, DEMO_SAMPLES } from '../model';
import { defaultGuidedOptions } from './contract';
import { toBackendProject } from './backendAdapter';

describe('no-code UI to R1.5 backend project schema translation', () => {
  it('turns a guided JSON draft into the exact backend 0.1 field groups and lowercase routing', () => {
    const draft = createDraft();
    draft.name = 'Synthetic Firewall';
    draft.vendor = 'Synthetic';
    draft.format = 'json';
    const result = toBackendProject(draft);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.project).toMatchObject({
      schemaRevision: '0.1',
      projectId: 'draft-demo_firewall',
      revision: 1,
      slug: 'demo_firewall',
      sourceCategory: 'network',
      receiver: {
        protocols: ['udp', 'tcp'],
        port: 6801,
        bindAddress: '0.0.0.0',
        messageLengthLimit: 8192,
        tcpFraming: 'line',
      },
      extraction: { format: 'json' },
      normalization: {
        topFields: {
          src_ip: { normalized_name: 'custom.source_ip', data_type: 'ip' },
          action: { normalized_name: 'custom.action', data_type: 'string' },
        },
        nsFields: { dst_port: { normalized_name: 'custom.destination_port', data_type: 'port' } },
        msgOriginSource: 'demo_firewall',
        msgClass: 'demo_firewall',
        msgOriginCategory: 'network',
      },
      classification: {
        defaultIndex: 'syslog',
        rules: [
          { field: 'custom.action', operator: 'equals', value: 'deny', index: 'threat' },
          { field: 'custom.action', operator: 'equals', value: 'allow', index: 'session' },
        ],
      },
    });
    expect(JSON.stringify(result.project)).not.toContain('198.51.100.10');
    expect(JSON.stringify(result.project)).not.toContain(DEMO_SAMPLES);
  });

  it('canonicalizes manufacturer whitespace before native output namespace serialization', () => {
    for (const vendor of [' Audit ', '\u00a0Audit\u00a0', '\u2003Audit\u2003']) {
      const draft = createDraft();
      draft.vendor = vendor;
      draft.format = 'json';
      const result = toBackendProject(draft);
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.project.vendor).toBe('Audit');
    }
  });

  it('rejects non-printing manufacturer namespaces before native generation', () => {
    for(const vendor of ['Audit\nInjected','Audit\u0000Bad','Audit\tBad',
      'Audit\u200bBad','Audit\u202eBad','Audit\u00adBad',
      'Audit\u034fBad','Audit\u115fBad','Audit\u2800Bad','Audit\u3164Bad',
      'Audit\uffa0Bad','트렌드마이크로','Palo\u00a0Alto','Café',
      '__proto__','constructor','prototype']){
      const draft=createDraft();draft.vendor=vendor;draft.format='json';
      const result=toBackendProject(draft);
      expect(result.ok,JSON.stringify(vendor)).toBe(false);
    }
    for(const vendor of ['Palo Alto Networks','A&B (Security)-2026_1.0']){
      const draft=createDraft();draft.vendor=vendor;draft.format='json';
      expect(toBackendProject(draft).ok,JSON.stringify(vendor)).toBe(true);
    }
  });

  it('maps timestamp to a supported backend date rule with explicit UTC', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({ id: 'when', source: 'event_time', target: 'custom.event_time', type: 'timestamp' });
    draft.guided = { ...defaultGuidedOptions(), sourceCategory: 'cloud', groups: { ...defaultGuidedOptions().groups, when: 'ns_fields' } };
    const result = toBackendProject(draft);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.project.sourceCategory).toBe('cloud');
    expect(result.project.normalization.nsFields.event_time).toEqual({
      normalized_name: 'custom.event_time', data_type: 'date', time_format: 'iso8601', timezone: 'UTC',
    });
  });

  it('qualifies a vendor-only classification source after normalization without changing the value', () => {
    const draft = createDraft();
    draft.format = 'kv';
    draft.vendor = 'Juniper';
    draft.guided = { ...defaultGuidedOptions(), groups: { ...defaultGuidedOptions().groups, action: 'vendor_fields' } };
    const result = toBackendProject(draft);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.project.classification.rules).toEqual([
      {field:'Juniper.custom.action',operator:'equals',value:'deny',index:'threat'},
      {field:'Juniper.custom.action',operator:'equals',value:'allow',index:'session'},
    ]);
  });

  it('routes an exact Juniper RFC5424 message identifier through the original vendor field', () => {
    const draft = createDraft();
    draft.format = 'syslog_rfc5424';
    draft.vendor = 'Juniper';
    draft.mappings.push({
      id:'msg-id',source:'syslog_msgid',target:'syslog_msgid',type:'string',
    });
    draft.guided = {
      ...defaultGuidedOptions(),
      classification:{defaultIndex:'Syslog',rules:[
        {id:'session-create',sourceField:'syslog_msgid',equals:'RT_FLOW_SESSION_CREATE',index:'Session'},
        {id:'session-close',sourceField:'syslog_msgid',equals:'RT_FLOW_SESSION_CLOSE',index:'Session'},
      ]},
      groups:{...defaultGuidedOptions().groups,'msg-id':'vendor_fields'},
    };
    const result = toBackendProject(draft);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.project.classification).toEqual({
      defaultIndex:'syslog',rules:[
        {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CREATE',index:'session'},
        {field:'Juniper.syslog_msgid',operator:'equals',value:'RT_FLOW_SESSION_CLOSE',index:'session'},
      ],
    });
  });

  it('fails closed if a vendor classification namespace has unsupported path characters', () => {
    const draft = createDraft();
    draft.format = 'kv';
    draft.vendor = 'Palo Alto Networks';
    draft.guided = {...defaultGuidedOptions(),groups:{...defaultGuidedOptions().groups,action:'vendor_fields'}};
    const result=toBackendProject(draft);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues.map(issue=>issue.code)).toContain('CLASSIFICATION_FIELD_PATH_UNSUPPORTED');
  });

  it('fails closed if a classifier source maps to more than one common destination', () => {
    const draft=createDraft();
    draft.format='kv';
    draft.mappings.push({id:'other-action',source:'action',target:'custom.other_action',type:'string'});
    draft.guided={...defaultGuidedOptions(),
      groups:{...defaultGuidedOptions().groups,'other-action':'ns_fields'}};
    const result=toBackendProject(draft);
    expect(result.ok).toBe(false);
    if(!result.ok)expect(result.issues.map(issue=>issue.code)).toContain('CLASSIFICATION_SOURCE_AMBIGUOUS');
  });

  it('rejects vendor classification on a numeric field instead of coercing to string', () => {
    const draft=createDraft();
    draft.format='kv';
    draft.vendor='Juniper';
    draft.mappings.push({id:'num-message',source:'event_number',target:'event_number',type:'integer'});
    draft.guided={...defaultGuidedOptions(),
      groups:{...defaultGuidedOptions().groups,'num-message':'vendor_fields'},
      classification:{defaultIndex:'Syslog',rules:[
        {id:'by-num',sourceField:'event_number',equals:'10',index:'Session'},
      ]}};
    const result=toBackendProject(draft);
    expect(result.ok).toBe(false);
    if(!result.ok)expect(result.issues.map(issue=>issue.code)).toContain('CLASSIFICATION_NONSTRING_FIELD');
  });

  it('rejects duplicate source keys instead of losing one mapping during object serialization', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({ id: 'other', source: 'src_ip', target: 'custom.duplicate_ip', type: 'ip' });
    draft.guided = { ...defaultGuidedOptions(), groups: { ...defaultGuidedOptions().groups, other: 'top_fields' } };
    const result = toBackendProject(draft);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((x) => x.code)).toContain('DUPLICATE_SOURCE');
  });

  it('blocks unsafe prototype fields immediately at local UI preflight, before backend requests', () => {
    const draft = createDraft();
    draft.format = 'json';
    draft.mappings.push({ id: 'hazard', source: '__proto__.key', target: 'custom.unsafe', type: 'string' });
    const result = toBackendProject(draft);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((x) => x.code)).toContain('UI_VALIDATION');
    expect(result.issues[0].message).toContain('Invalid source field');
  });

  it('supports only bounded named-capture Regex and still fails closed on invalid transport', () => {
    const draft = createDraft();
    expect(toBackendProject(draft).ok).toBe(false);

    draft.format = 'regex';
    const regex = toBackendProject(draft);
    expect(regex.ok).toBe(true);
    if (regex.ok) expect(regex.project.extraction).toEqual({
      format: 'regex', pattern: draft.pattern,
    });

    draft.pattern = '(a+)+$';
    expect(toBackendProject(draft).ok).toBe(false);

    draft.format = 'json';
    draft.guided = { ...defaultGuidedOptions(), receiver: { ...defaultGuidedOptions().receiver, protocols: [], port: 22 } };
    expect(toBackendProject(draft).ok).toBe(false);
  });
  it('produces backend-compatible comma CSV metadata with the entered column order', () => {
    const draft = createDraft();
    draft.format = 'csv';
    draft.csvColumns = 'action,src_ip,dst_port';
    const converted = toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if (converted.ok) expect(converted.project.extraction).toEqual({
      format: 'csv', csvColumns: ['action', 'src_ip', 'dst_port'], csvDelimiter: ',',
    });
  });

  it.each([
    [';', ['action', 'src_ip', 'dst_port']],
    ['\t', ['action', 'src_ip', 'dst_port']],
  ] as const)('passes reviewed CSV delimiter %s to the backend JSON contract', (delimiter, columns) => {
    const draft = createDraft(); draft.format = 'csv';
    draft.csvColumns = 'action,src_ip,dst_port';
    draft.csvDelimiter = delimiter;
    const project = toBackendProject(draft);
    expect(project.ok).toBe(true);
    if (project.ok) expect(project.project.extraction).toEqual({
      format: 'csv', csvColumns: columns, csvDelimiter: delimiter,
    });
  });

  it('rejects unexpected data delimiter rather than producing a wrong draft artifact', () => {
    const draft = createDraft(); draft.format = 'csv';
    draft.csvDelimiter = '|' as ',';
    expect(toBackendProject(draft).ok).toBe(false);
  });

  it.each(['', 'action,action', '1bad,action', 'action,first-name', 'action,,src_ip'])(
    'fails closed on ambiguous or invalid CSV columns: %s', (columns) => {
      const draft = createDraft();
      draft.format = 'csv';
      draft.csvColumns = columns;
      expect(toBackendProject(draft).ok).toBe(false);
    },
  );

});

describe('receiver bind default matches installed Stellar customized parsers', () => {
  const projectFor = (policy?: 'loopback' | 'all') => {
    const draft = createDraft();
    draft.format = 'json';
    if (policy) draft.guided = { ...defaultGuidedOptions(), receiver: { ...defaultGuidedOptions().receiver, bindPolicy: policy } };
    const result = toBackendProject(draft);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    return result.project as { receiver: { bindAddress: string } };
  };

  it('defaults to all interfaces (0.0.0.0), as in every reference CONF source', () => {
    expect(defaultGuidedOptions().receiver.bindPolicy).toBe('all');
    expect(projectFor().receiver.bindAddress).toBe('0.0.0.0');
  });

  it('keeps an explicit loopback override', () => {
    expect(projectFor('loopback').receiver.bindAddress).toBe('127.0.0.1');
    expect(projectFor('all').receiver.bindAddress).toBe('0.0.0.0');
  });
});
