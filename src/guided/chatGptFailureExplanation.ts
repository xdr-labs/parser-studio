/** Source-safe, aggregate-only failure details for novice ChatGPT repair review. */
interface Counters {
 fieldRemovals:number;
 typeChanges:number;
 positiveAfter:number;
 sourceCount:number;
 regressions:number;
}
type HoldoutIndependenceEvidence=
 | {ok:true}
 | {ok:false;reason:'TOO_SMALL'|'TRAINING_OVERLAP'|'IDENTICAL_TO_TRAINING';
    holdoutUnique:number;requiredUnique:number;overlapCount:number};
export interface CandidateFailureEvidence {
 baseline:Counters;
 holdout:Counters|null;
 holdoutIndependence?:HoldoutIndependenceEvidence|null;
}
/** Original-sample result that is not hidden by a rejected set of additional examples. */
export function originalLogsStillPass({baseline,holdoutStatus,acceptedWithoutRegression}:{
 baseline:Counters;holdoutStatus:string;acceptedWithoutRegression:boolean;
}):boolean {
 if(holdoutStatus!=='REJECTED')return acceptedWithoutRegression;
 return baseline.regressions===0&&baseline.fieldRemovals===0&&baseline.typeChanges===0&&
   baseline.positiveAfter>=baseline.sourceCount;
}
export function explainRejectedChatGPTFix({baseline,holdout,holdoutIndependence}:CandidateFailureEvidence):string {
 if(holdoutIndependence&&!holdoutIndependence.ok){
  if(holdoutIndependence.reason==='IDENTICAL_TO_TRAINING')
   return 'Blocked: The additional examples are the same as the original sample. '+
     'Paste different log lines that were not used to create this fix.';
  if(holdoutIndependence.reason==='TRAINING_OVERLAP')
   return 'Blocked: '+holdoutIndependence.overlapCount+
     ' additional example(s) also appear in the original sample. Remove them and add different log lines.';
  return 'Blocked: Add at least '+holdoutIndependence.requiredUnique+
    ' different additional examples; '+holdoutIndependence.holdoutUnique+
    ' unique example(s) were supplied.';
 }
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
