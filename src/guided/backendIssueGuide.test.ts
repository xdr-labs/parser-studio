import { describe, expect, it } from 'vitest';
import { backendIssueTarget } from './backendIssueGuide';

describe('backend schema issue recovery in six-stage builder', () => {
  it.each([
    ['/slug', 0, 'Go to Parser Details'],
    ['/receiver/port', 3, 'Go to Receiver Settings'],
    ['/extraction/csvColumns/0', 1, 'Go to Extraction Settings'],
    ['/normalization/nsFields/action', 2, 'Go to Mapping'],
    ['/mappings/0', 2, 'Go to Mapping'],
    ['/classification/rules/0', 3, 'Go to Classification Settings'],
    ['/other/unknown', 5, 'Review Validation Details'],
  ])('maps %s to the correct edit step', (path, step, label) => {
    expect(backendIssueTarget(path)).toEqual({ step, label });
  });
});
