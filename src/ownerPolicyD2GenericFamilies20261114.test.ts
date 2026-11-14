/**
 * Owner policy D-2 (decided 2026-11-14): a line that claims to be CEF or LEEF inside Generic Structural.
 *
 *  - A newly created Generic Structural parser carries genericStructuralFamilyGrammar 'dedicated': such a line
 *    is read by the CEF/LEEF grammar or declined. It is never read as generic key=value and shown as FULL.
 *  - A project created before the decision carries no marker and keeps its V15 result exactly (legacy
 *    compatibility route). Its verdict for such a line is PARTIAL with a warning, never FULL, and the
 *    warning does not block the project.
 *  - A backend that does not advertise the dedicated grammar is refused before download.
 *
 * The lines are the Semantic Oracle's (contracts/semantic-goldens.v1.json, ownerPolicies.D-2), which holds
 * the generated Ruby (Ruby 2.4.9) to the same expectations.
 */
import { describe, expect, it } from 'vitest';
import goldens from '../contracts/semantic-goldens.v1.json';
import { preview } from './parser';
import { createDraft, type ParserDraft } from './model';
import { lookupFieldValue } from './fieldPaths';
import { extractGenericStructural } from './genericStructural';
import { selectDraftFormat } from './guided/draftFormatTransition';
import { buildAutomaticGenericStructuralDraft } from './guided/genericStructuralAutoDraft';
import { toBackendProject } from './guided/backendAdapter';
import { assertBackendProjectSupported, type BackendCapabilities } from './guided/backendCapabilities';
import { validLocalDraft } from './guided/localWorkspaceHistory';

interface GenericCase { id: string; raw: string; familyGrammar?: string; expect: { fields?: Record<string, unknown>; reject?: boolean; status?: string } }
const CASES = (goldens.genericCases as GenericCase[]).filter(item => item.id.startsWith('generic-d2-'));
const draftFor = (item: GenericCase): ParserDraft => ({ ...createDraft(), format: 'generic_structural',
  ...(item.familyGrammar === 'dedicated' ? { genericStructuralFamilyGrammar: 'dedicated' as const } : {}) });
const CEF = 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=80 act=blocked proto=tcp';

describe('owner policy D-2: CEF/LEEF inside Generic Structural', () => {
  it('covers the legacy route, the dedicated grammar and declined claims', () => {
    expect(CASES.filter(item => !item.familyGrammar && item.expect.status === 'PARTIAL').length).toBeGreaterThanOrEqual(4);
    expect(CASES.filter(item => item.familyGrammar === 'dedicated' && item.expect.status === 'FULL').length).toBeGreaterThanOrEqual(4);
    expect(CASES.filter(item => item.familyGrammar === 'dedicated' && item.expect.reject).length).toBeGreaterThanOrEqual(4);
  });

  it.each(CASES.map(item => [item.id, item] as const))('%s', (_id, item) => {
    const event = preview(item.raw, draftFor(item)).events[0]!;
    const codes = event.diagnostics.map(diagnostic => diagnostic.code);
    expect(event.raw).toBe(item.raw);
    if (item.expect.reject) {
      expect(event.parseStatus).toBe('UNKNOWN');
      expect(event.extracted).toBe(false);
      expect(event.fields).toEqual({});
      expect(event.diagnostics.map(diagnostic => diagnostic.message).join('\n')).toMatch(/claims to be (CEF|LEEF) but does not match/);
      return;
    }
    expect(event.extracted).toBe(true);
    for (const [path, want] of Object.entries(item.expect.fields ?? {})) expect(lookupFieldValue(event.fields, path)).toEqual({ found: true, value: want });
    expect(event.parseStatus).toBe(item.expect.status);
    if (item.expect.status === 'PARTIAL') {
      // Never FULL, and reported as a warning so that an existing project keeps working.
      const warning = event.diagnostics.find(diagnostic => diagnostic.code === 'GENERIC_STRUCTURAL_NOT_FULL')!;
      expect(warning.severity).toBe('warning');
      expect(warning.message).toMatch(/claims to be (CEF|LEEF) but was read as generic key=value/);
      expect(event.diagnostics.filter(diagnostic => diagnostic.stage === 'extract' && diagnostic.severity === 'error')).toEqual([]);
    } else {
      expect(codes).not.toContain('GENERIC_STRUCTURAL_NOT_FULL');
    }
  });

  it('the legacy route returns the V15 result unchanged', () => {
    expect(extractGenericStructural(CEF)).toEqual({ errors: [], fields: { generic: { mode: 'space_kv', source_raw: CEF,
      kv: { dst: '2.1.2.2', spt: '1232', dpt: '80', act: 'blocked', proto: 'tcp' },
      prefix_001: 'CEF:0|Security|threatmanager|1.0|100|worm', prefix_002: 'successfully', prefix_003: 'stopped|10|src=10.0.0.1' } } });
  });

  it('the dedicated grammar reads the header and the first extension field that the legacy route leaves in prefix text', () => {
    const { fields, errors } = extractGenericStructural(CEF, undefined, 'dedicated');
    expect(errors).toEqual([]);
    expect(fields.body).toMatchObject({ cef_device_vendor: 'Security', cef_name: 'worm successfully stopped', cef_severity: '10', src: '10.0.0.1', proto: 'tcp' });
    expect(fields.generic).toEqual({ mode: 'structured_family_cef', source_raw: CEF });
  });

  it('a newly selected Generic Structural parser is dedicated; an existing one keeps its route; another format drops the marker', () => {
    const fresh = selectDraftFormat({ ...createDraft(), format: 'kv' }, 'generic_structural');
    expect(fresh.genericStructuralFamilyGrammar).toBe('dedicated');
    const legacy: ParserDraft = { ...createDraft(), format: 'generic_structural' };
    expect(selectDraftFormat(legacy, 'generic_structural').genericStructuralFamilyGrammar).toBeUndefined();
    expect(selectDraftFormat(fresh, 'generic_structural').genericStructuralFamilyGrammar).toBe('dedicated');
    expect(selectDraftFormat(fresh, 'kv').genericStructuralFamilyGrammar).toBeUndefined();
  });

  it('the stored draft accepts the marker only on Generic Structural', () => {
    const generic: ParserDraft = { ...createDraft(), format: 'generic_structural' };
    expect(validLocalDraft({ ...generic, genericStructuralFamilyGrammar: 'dedicated' })).toBe(validLocalDraft(generic));
    expect(validLocalDraft({ ...createDraft(), format: 'kv', genericStructuralFamilyGrammar: 'dedicated' })).toBe(false);
    expect(validLocalDraft({ ...generic, genericStructuralFamilyGrammar: 'legacy' })).toBe(false);
  });

  describe('automatic draft and backend', () => {
    const source = '<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected src=192.0.2.40 dst=198.51.100.5 action=block user="alice"';
    const capability = (dedicated?: boolean): BackendCapabilities => ({
      contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
      authoring: { receiverProtocols: ['udp', 'tcp'], extractionFormats: ['generic_structural'],
        genericStructuralGrammar: 'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',
        genericStructuralProfiles: ['syslog_prefix_kv', 'leef2_implicit_tab'],
        ...(dedicated === undefined ? {} : { genericStructuralDedicatedFamilies: dedicated }),
        formatCoverage: 'reviewed-bounded-subset', httpReceiver: false,
        multipleDistinctReceiverPorts: false, multiline: false, arbitraryRuby: false },
      import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
      verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
      limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
    });
    const built = () => {
      const result = buildAutomaticGenericStructuralDraft(source, createDraft());
      if (!result) throw new Error('The source did not produce a Generic Structural draft');
      return result.draft;
    };

    it('an automatically built parser is dedicated and says so to the backend', () => {
      const draft = built();
      expect(draft.genericStructuralFamilyGrammar).toBe('dedicated');
      const converted = toBackendProject(draft);
      if (!converted.ok) throw new Error(JSON.stringify(converted.issues));
      expect(converted.project.extraction).toMatchObject({ format: 'generic_structural', genericStructuralFamilyGrammar: 'dedicated' });
      expect(() => assertBackendProjectSupported(converted.project, capability(true))).not.toThrow();
    });

    it.each([[undefined], [false]])('a backend whose dedicated-grammar capability is %s is refused', claim => {
      const converted = toBackendProject(built());
      if (!converted.ok) throw new Error(JSON.stringify(converted.issues));
      let rejected: unknown;
      try { assertBackendProjectSupported(converted.project, capability(claim)); } catch (error) { rejected = error; }
      expect(rejected).toMatchObject({ code: 'BACKEND_PROFILE_UNSUPPORTED' });
    });

    it('a legacy project (no marker) is still accepted by a backend without the capability', () => {
      const legacy = { ...built() };
      delete legacy.genericStructuralFamilyGrammar;
      const converted = toBackendProject(legacy);
      if (!converted.ok) throw new Error(JSON.stringify(converted.issues));
      expect(converted.project.extraction).not.toHaveProperty('genericStructuralFamilyGrammar');
      expect(() => assertBackendProjectSupported(converted.project, capability())).not.toThrow();
    });

    it('the marker on another format is not translated', () => {
      const wrong = toBackendProject({ ...built(), format: 'kv', genericStructuralFamilyGrammar: 'dedicated' } as ParserDraft);
      expect(wrong.ok).toBe(false);
      if (!wrong.ok) expect(wrong.issues.map(issue => issue.code)).toContain('GENERIC_STRUCTURAL_FAMILY_GRAMMAR');
    });
  });
});
