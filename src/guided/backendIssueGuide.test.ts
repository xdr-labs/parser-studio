import { describe, expect, it } from 'vitest';
import { backendIssueTarget } from './backendIssueGuide';

describe('backend schema issue recovery in six-stage builder', () => {
  it.each([
    ['/slug', 0, '기본 정보로 이동'],
    ['/receiver/port', 3, '수신 설정으로 이동'],
    ['/extraction/csvColumns/0', 1, '추출 설정으로 이동'],
    ['/normalization/nsFields/action', 2, '필드 매핑으로 이동'],
    ['/mappings/0', 2, '필드 매핑으로 이동'],
    ['/classification/rules/0', 3, '분류 설정으로 이동'],
    ['/other/unknown', 5, '검증 내용 확인'],
  ])('maps %s to the correct edit step', (path, step, label) => {
    expect(backendIssueTarget(path)).toEqual({ step, label });
  });
});
