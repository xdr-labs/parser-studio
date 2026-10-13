import { describe, expect, it } from 'vitest';
import { starterTemplateIds, loadStarterTemplate } from './sampleTemplates';
import { preview } from '../parser';
import { toBackendProject } from './backendAdapter';

describe('safe synthetic no-code starter templates', () => {
  it('provides six base formats and two explicit RFC5424 envelope variants', () => {
    expect(starterTemplateIds).toEqual([
      'json', 'kv', 'csv', 'rfc3164_kv', 'syslog_rfc5424', 'rfc5424_cef', 'rfc5424_leef', 'cef', 'leef', 'mixed', 'mixed_rfc5424', 'mixed_rfc3164', 'mixed_rfc5424_bodies',
    ]);
  });
  it.each(['json','kv','csv','syslog_rfc5424','cef','leef'] as const)(
    '%s provides a complete sample and compatible draft without proprietary values', (id) => {
      const template = loadStarterTemplate(id);
      expect(template.label.length).toBeGreaterThan(2);
      expect(template.sample.includes('\n')).toBe(true);
      expect(template.draft.format).toBe(id);
      expect(template.draft.guided?.eventBoundary).toBe('single-line');
      expect(template.draft.guided?.classification.defaultIndex).toBe('Syslog');
      expect(template.draft.guided?.slug).toMatch(/^[a-z][a-z0-9_]{2,47}$/);
      expect(template.draft.csvColumns).toBe('action,src_ip,dst_port');
      const suite = preview(template.sample, template.draft);
      expect(suite.counts.total).toBe(2);
      expect(suite.counts.matched).toBe(2);
      expect(suite.counts.normalized).toBe(2);
      expect(suite.counts.failures).toBe(0);
      const project = toBackendProject(template.draft);
      expect(project.ok).toBe(true);
      if (project.ok) {
        expect(project.project.extraction.format).toBe(id);
        expect(JSON.stringify(project.project)).not.toContain('198.51.100.');
        expect(JSON.stringify(project.project)).not.toContain('203.0.113.');
      }
      expect(template.sample).not.toContain('localhost password');
    },
  );
  it('provides a strict RFC3164 year/zone-unknown KV starter without date inference',()=>{
    const preset=loadStarterTemplate('rfc3164_kv');
    expect(preset.draft.format).toBe('syslog_rfc3164');
    expect(preset.draft.syslogBodyFormat).toBe('kv');
    expect(preset.draft.mappings.find(x=>x.source==='syslog_time_policy')?.type).toBe('string');
    expect(preview(preset.sample,preset.draft).counts)
      .toMatchObject({total:2,matched:2,normalized:2,failures:0});
    const mapped=toBackendProject(preset.draft);
    expect(mapped.ok).toBe(true);
    if(mapped.ok)expect(mapped.project.extraction)
      .toEqual({format:'syslog_rfc3164',syslogBodyFormat:'kv'});
  });
  it.each([
    ['rfc5424_cef','cef'],
    ['rfc5424_leef','leef'],
  ] as const)('the synthetic %s envelope includes explicit %s extraction/mappings and classification', (id,mode) => {
    const template=loadStarterTemplate(id);
    expect(template.draft.format).toBe('syslog_rfc5424');
    expect(template.draft.syslogBodyFormat).toBe(mode);
    expect(template.draft.guided?.eventBoundary).toBe('single-line');
    expect(template.draft.mappings.map(mapping=>mapping.source)).toContain('body.act');
    const suite=preview(template.sample,template.draft);
    expect(suite.counts).toMatchObject({total:2,matched:2,normalized:2,failures:0});
    const project=toBackendProject(template.draft);
    expect(project.ok).toBe(true);
    if(project.ok){
      expect(project.project.extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:mode});
      expect(JSON.stringify(project.project)).not.toContain('198.51.100.10');
      expect(JSON.stringify(project.project)).not.toContain('203.0.113.11');
      expect(project.project.classification.rules[0].field).toBe('custom.action');
    }
  });

  it('offers strict RFC5424-wrapped JSON/KV and standalone JSON/KV synthetic starter',()=>{
    const template=loadStarterTemplate('mixed_rfc5424_bodies');
    expect(template.draft.format).toBe('mixed');
    expect(template.draft.mixedFormats).toEqual(['json','kv','rfc5424_json','rfc5424_kv']);
    expect(template.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
    const report=preview(template.sample,template.draft);
    expect(report.counts).toMatchObject({total:4,matched:4,normalized:4,failures:0});
    expect(report.events[2]?.fields).toMatchObject({
      body:{src_ip:'192.0.2.19',action:'deny'},
      syslog_timestamp:'2026-10-12T01:02:03Z'});
    const backend=toBackendProject(template.draft);
    expect(backend.ok).toBe(true);
    if(backend.ok)expect(backend.project.extraction).toEqual({
      format:'mixed',mixedFormats:['json','kv','rfc5424_json','rfc5424_kv']});
    expect(JSON.stringify(backend)).not.toContain('203.0.113.4');
  });
  it('offers strict yearless RFC3164 TAG KV + JSON/KV synthetic mixed sample',()=>{
    const preset=loadStarterTemplate('mixed_rfc3164');
    expect(preset.draft.format).toBe('mixed');
    expect(preset.draft.mixedFormats).toEqual(['json','kv','rfc3164_kv']);
    expect(preset.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
    expect(preset.draft.mappings.some(m=>m.source==='syslog_timestamp'&&m.type==='timestamp')).toBe(false);
    const suite=preview(preset.sample,preset.draft);
    expect(suite.counts).toMatchObject({total:3,matched:3,normalized:3,failures:0});
    expect(suite.events[2]?.fields).toMatchObject({
      syslog_time_policy:'YEAR_AND_ZONE_UNKNOWN'});
    const result=toBackendProject(preset.draft);
    expect(result.ok).toBe(true);
    if(result.ok){
      expect(result.project.extraction).toEqual({
        format:'mixed',mixedFormats:['json','kv','rfc3164_kv']});
      expect(result.project.receiver.port).toBe(preset.draft.guided?.receiver.port);
    }
  });
  it('offers a reviewed synthetic mixed RFC5424 CEF/LEEF starter with the same sensor/CONF port',()=>{
    const template=loadStarterTemplate('mixed_rfc5424');
    expect(template.draft.format).toBe('mixed');
    expect(template.draft.mixedFormats).toEqual(['json','rfc5424_cef','rfc5424_leef']);
    expect(template.draft.guided?.receiver.port).toBeGreaterThanOrEqual(6800);
    expect(preview(template.sample,template.draft).counts).toMatchObject({
      total:3,matched:3,normalized:3,failures:0,
    });
    const result=toBackendProject(template.draft);
    expect(result.ok).toBe(true);
    if(result.ok){
      expect(result.project.extraction).toEqual({
        format:'mixed',mixedFormats:['json','rfc5424_cef','rfc5424_leef'],
      });
      expect(result.project.receiver.port).toBe(template.draft.guided?.receiver.port);
      expect(JSON.stringify(result)).not.toContain('203.0.113.8');
    }
  });
  it('offers a fully explicit four-format synthetic mix without silent fallback',()=>{
    const preset=loadStarterTemplate('mixed');
    expect(preset.draft.mixedFormats).toEqual(['json','kv','cef','leef']);
    expect(preset.draft.format).toBe('mixed');
    expect(preview(preset.sample,preset.draft).counts)
      .toMatchObject({total:4,matched:4,normalized:4,failures:0});
    const adapted=toBackendProject(preset.draft);
    expect(adapted.ok).toBe(true);
    if(adapted.ok)expect(adapted.project.extraction).toEqual({
      format:'mixed',mixedFormats:['json','kv','cef','leef']
    });
    expect(JSON.stringify(adapted)).not.toContain('203.0.113.11');
  });
  it('constructs a fresh, mutable draft for each selection rather than reusing shared project rules', () => {
    const first = loadStarterTemplate('cef');
    const again = loadStarterTemplate('cef');
    first.draft.mappings[0].source = 'tampered';
    first.draft.guided!.receiver.port = 8080;
    expect(again.draft.mappings[0].source).not.toBe('tampered');
    expect(again.draft.guided!.receiver.port).toBe(7501);
  });
});
