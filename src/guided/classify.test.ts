import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { defaultGuidedOptions } from './contract';
import { suggestClassification } from './classify';

describe('explainable local classification suggestions', () => {
  it('routes preview extracted event fields with transparent first-match priority', () => {
    const draft = createDraft();
    const events = preview('{"action":"allow"}\naction=deny\n{"action":"other"}', draft).events;
    const options = defaultGuidedOptions();
    expect(suggestClassification(events[0], options)).toMatchObject({ index: 'Session', rule: 1, status: 'matched' });
    expect(suggestClassification(events[1], options)).toMatchObject({ index: 'Threat', rule: 0, status: 'matched' });
    expect(suggestClassification(events[2], options)).toMatchObject({ index: 'Syslog', rule: null, status: 'fallback' });
  });

  it('never assigns a green classification when extracting a log has failed', () => {
    const events = preview('not recognizable', createDraft()).events;
    expect(suggestClassification(events[0], defaultGuidedOptions())).toMatchObject({ index: null, status: 'unresolved' });
  });

  it('supports nested JSON own-key path conditions but does not inspect object prototypes', () => {
    const draft = createDraft();
    const event = preview('{"session":{"outcome":"deny"}}', draft).events[0];
    const options = defaultGuidedOptions();
    options.classification.rules = [{ id: 'nested', sourceField: 'session.outcome', equals: 'deny', index: 'Threat' }];
    expect(suggestClassification(event, options).index).toBe('Threat');
    options.classification.rules = [{ id: 'proto', sourceField: 'constructor', equals: '[object Object]', index: 'Threat' }];
    expect(suggestClassification(event, options).status).toBe('fallback');
  });

  it('matches an exact dotted KV source field before attempting nested JSON traversal', () => {
    const draft=createDraft();
    draft.format='kv';
    const event=preview('event.action=deny src_ip=198.51.100.10', draft).events[0];
    expect(event.fields['event.action']).toBe('deny');
    const options=defaultGuidedOptions();
    options.classification.rules = [
      {id:'flat-dot',sourceField:'event.action',equals:'deny',index:'Threat'},
    ];
    expect(suggestClassification(event,options)).toMatchObject({
      index:'Threat',rule:0,status:'matched',
    });
  });

  it('has case-sensitive exact conditions, never claiming native routing success', () => {
    const event = preview('{"action":"DENY"}', createDraft()).events[0];
    const result = suggestClassification(event, defaultGuidedOptions());
    expect(result.status).toBe('fallback');
    expect(result.reason).toContain('기본 이벤트');
  });
});
