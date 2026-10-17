/**
 * Backward-compatible isolated PoC import. The original reviewed scanner was
 * moved, not reimplemented; all production/synthetic paths share its grammar.
 */
export {inspectSourceCompleteness} from '../standardSourceCompletenessGate';
export type {
  SourceCompletenessFamily, SourceCompletenessInspection,
  SourceCompletenessIssue,
} from '../standardSourceCompletenessGate';
