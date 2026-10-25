/** Source-safe, aggregate-only failure details for novice ChatGPT repair review. */
interface Counters {
 fieldRemovals:number;
 typeChanges:number;
 positiveAfter:number;
 sourceCount:number;
 regressions:number;
}
export interface CandidateFailureEvidence {
 baseline:Counters;
 holdout:Counters|null;
}
export function explainRejectedChatGPTFix({baseline,holdout}:CandidateFailureEvidence):string {
 if(baseline.fieldRemovals>0)
  return 'Blocked: The proposed parser would remove '+baseline.fieldRemovals+
    ' previously extracted original field path(s). Preserve them in the next proposal.';
 if(baseline.typeChanges>0)
  return 'Blocked: The proposed parser would change '+baseline.typeChanges+
    ' original field type(s). Review the field mappings.';
 if(baseline.regressions>0)
  return 'Blocked: The proposal would regress '+baseline.regressions+
    ' previously passing original event(s).';
 if(baseline.positiveAfter<baseline.sourceCount)
  return 'Blocked: The proposed parser did not successfully parse every original event.';
 if(holdout?.fieldRemovals)
  return 'Blocked: The proposal would remove '+holdout.fieldRemovals+
    ' previously extracted field path(s) from the additional examples.';
 if(holdout?.typeChanges)
  return 'Blocked: The proposal would change '+holdout.typeChanges+
    ' previously extracted field type(s) from the additional examples.';
 if(holdout?.regressions)
  return 'Blocked: The proposal would regress '+holdout.regressions+
    ' previously passing additional event(s).';
 if(holdout&&holdout.positiveAfter<holdout.sourceCount)
  return 'Blocked: The proposed parser did not successfully parse every additional test event.';
 return 'Blocked: The original or additional examples failed field-preservation checks.';
}
