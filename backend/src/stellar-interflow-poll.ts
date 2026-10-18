/**
 * Bounded, abortable Interflow polling over an already-authorized read
 * callback. No background daemon, network target, credentials or cursor
 * invention. Read/audit/identity policies must be enforced by the caller
 * on EVERY attempt, not once at the start of a long-lived polling request.
 */
import type {InterflowFieldResult} from "./stellar-interflow.js";

export type InterflowPollOptions={
  maxAttempts:number;
  intervalMs:number;
  signal:AbortSignal;
};
export type InterflowPollResult=InterflowFieldResult & {
  attempts:number;
  cursorVerified:false;
  searchPermissionsVerified:false;
};
export class InterflowPollError extends Error{
  constructor(readonly code:string){super(code);this.name="InterflowPollError";}
}
const fail=(code:string):never=>{throw new InterflowPollError(code);};
function wait(ms:number,signal:AbortSignal):Promise<void>{
  return new Promise((resolve,reject)=>{
    if(signal.aborted){reject(new InterflowPollError("INTERFLOW_POLL_CANCELLED"));return;}
    let settled=false;
    const timer=setTimeout(()=>{
      if(settled)return;
      settled=true;signal.removeEventListener("abort",onAbort);resolve();
    },ms);
    const onAbort=()=>{
      if(settled)return;
      settled=true;clearTimeout(timer);
      signal.removeEventListener("abort",onAbort);
      reject(new InterflowPollError("INTERFLOW_POLL_CANCELLED"));
    };
    signal.addEventListener("abort",onAbort,{once:true});
    if(signal.aborted)onAbort();
  });
}
export async function pollBoundedInterflow(
  readOne:()=>Promise<InterflowFieldResult>,
  options:InterflowPollOptions
):Promise<InterflowPollResult>{
  if(!options||!Number.isInteger(options.maxAttempts)||
    options.maxAttempts<1||options.maxAttempts>6||
    !Number.isInteger(options.intervalMs)||
    options.intervalMs<250||options.intervalMs>3000||
    options.maxAttempts*options.intervalMs>15000||
    !(options.signal instanceof AbortSignal))
    fail("INTERFLOW_POLL_LIMITS_INVALID");
  const seal=(result:InterflowFieldResult,attempts:number):InterflowPollResult=>({
    ...result,attempts,cursorVerified:false,searchPermissionsVerified:false,
  });
  let last:InterflowFieldResult|null=null;
  for(let attempt=1;attempt<=options.maxAttempts;attempt++){
    if(options.signal.aborted)fail("INTERFLOW_POLL_CANCELLED");
    // Network/auth/permission exceptions deliberately propagate: NO retry
    // for a 403, 401 refresh failure, transport error or malformed response.
    const current=await readOne();
    if(options.signal.aborted)fail("INTERFLOW_POLL_CANCELLED");
    if(current.state==="MATCHED_RESPONSE_FIELDS")return seal(current,attempt);
    if(current.state==="FIELD_MISMATCH"||
      (current.state==="NO_MATCH"&&last===null))last=current;
    if(attempt<options.maxAttempts)await wait(options.intervalMs,options.signal);
  }
  if(last===null)throw new InterflowPollError("INTERFLOW_POLL_NO_EVIDENCE");
  return seal(last,options.maxAttempts);
}
