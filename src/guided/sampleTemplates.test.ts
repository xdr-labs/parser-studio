import { describe, expect, it } from 'vitest';
import { starterTemplateIds, loadStarterTemplate } from './sampleTemplates';
import { preview } from '../parser';
import { toBackendProject } from './backendAdapter';

describe('safe synthetic no-code starter templates', () => {
  it('provides exactly six distinct reviewed log families', () => {
    expect(starterTemplateIds).toEqual([
      'json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef',
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
  it('constructs a fresh, mutable draft for each selection rather than reusing shared project rules', () => {
    const first = loadStarterTemplate('cef');
    const again = loadStarterTemplate('cef');
    first.draft.mappings[0].source = 'tampered';
    first.draft.guided!.receiver.port = 8080;
    expect(again.draft.mappings[0].source).not.toBe('tampered');
    expect(again.draft.guided!.receiver.port).toBe(7501);
  });
});
