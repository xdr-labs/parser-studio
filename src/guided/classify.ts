import type { EventResult } from '../model';
import type { EventClass, GuidedOptions } from './contract';

export interface ClassificationHint {
  index: EventClass | null;
  rule: number | null;
  reason: string;
  status: 'matched' | 'fallback' | 'unresolved';
}

/** Browser-only ordered if/then hint; NOT evidence of real Fluentd rewrite-tag or target upload. */
export function suggestClassification(event: EventResult, options: GuidedOptions): ClassificationHint {
  if (!event.matched) {
    return { index: null, rule: null, status: 'unresolved', reason: '이벤트 추출에 실패하여 분류할 수 없습니다.' };
  }
  for (let i = 0; i < options.classification.rules.length; i++) {
    const rule = options.classification.rules[i];
    if (!rule.sourceField.trim() || !rule.equals.trim()) continue;
    const parts = rule.sourceField.split('.');
    let value: unknown = event.fields;
    for (const part of parts) {
      if (!value || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, part)) {
        value = undefined;
        break;
      }
      value = (value as Record<string, unknown>)[part];
    }
    if (value !== undefined && value !== null && String(value) === rule.equals) {
      return { index: rule.index, rule: i, status: 'matched', reason: rule.sourceField + ' = ' + rule.equals + ' · 조건 ' + (i + 1) };
    }
  }
  return { index: options.classification.defaultIndex, rule: null, status: 'fallback', reason: '일치 조건 없음 · 기본 이벤트 유형 적용' };
}
