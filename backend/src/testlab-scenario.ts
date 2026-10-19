/**
 * Pure, bounded multi-sample Test Lab scenario planner.
 *
 * Constant mode rotates curated source families at an approved steady rate.
 * Original-gaps mode uses an explicitly supplied sequence of relative
 * offsets (not guessed from unknown vendor raw timestamp formats).
 * Nothing sends logs or uses a tenant/DP/credential in this module.
 */
import {createSyntheticPreview,SyntheticPreviewError,
  type SyntheticPreviewRequest,type SyntheticPreview} from "./testlab-synthetic.js";

export type ScenarioMode="constant-rate"|"original-gaps";
export type ScenarioEntry={
  id:string;
  offsetMs?:number;
  sample:SyntheticPreviewRequest;
};
export type ReplayScenario={
  scenarioId:string;
  mode:ScenarioMode;
  cycleMs?:number;
  events:readonly ScenarioEntry[];
};
export type ScenarioEvidence={
  contract:"parser-studio.synthetic-scenario.v0.1";
  replayMode:ScenarioMode;
  sampleFamilyCount:number;
  safeToSendToSensor:false;
  sensorReceivedVerified:false;
  runtimeParsingVerified:false;
};
export type ScenarioPick={
  sampleId:string;
  nextDelayMs:number;
  preview:SyntheticPreview;
};
export class ScenarioContractError extends Error{
  constructor(readonly code:string){super(code);this.name="ScenarioContractError";}
}
const fail=(code:string):never=>{throw new ScenarioContractError(code);};
const ID=/^[a-z][a-z0-9_-]{1,63}$/;
const RUN=/^test_run_[0-9a-f]{32}$/;
const PREVIEW_FIELDS=new Set([
  "format","source","seed","sequence","timestampField","variableFields",
  "runMarkerField","csvColumns","csvDelimiter","syslogBodyFormat",
]);

export function validateReplayScenario(scenario:ReplayScenario,
  maxRatePerSecond:number):ScenarioEvidence{
  if(!Number.isFinite(maxRatePerSecond)||maxRatePerSecond<0.2||
    maxRatePerSecond>5)fail("TESTLAB_SCENARIO_RATE_INVALID");
  if(!scenario||typeof scenario!=="object"||
    !ID.test(scenario.scenarioId)||
    !["constant-rate","original-gaps"].includes(scenario.mode)||
    !Array.isArray(scenario.events)||scenario.events.length<2||
    scenario.events.length>12)fail("TESTLAB_SCENARIO_INVALID");
  if(Object.keys(scenario).some(key=>!["scenarioId","mode","cycleMs","events"].includes(key)))
    fail("TESTLAB_SCENARIO_INVALID");
  const seen=new Set<string>();
  const minInterval=Math.ceil(1000/maxRatePerSecond);
  if(scenario.mode==="constant-rate"){
    if(scenario.cycleMs!==undefined)fail("TESTLAB_SCENARIO_TIMING_INVALID");
  }else if(!Number.isInteger(scenario.cycleMs)||
    scenario.cycleMs!<minInterval*scenario.events.length||
    scenario.cycleMs!>15000)
    fail("TESTLAB_SCENARIO_TIMING_INVALID");
  let lastOffset=0;
  for(const [index,entry] of scenario.events.entries()){
    if(!entry||typeof entry!=="object"||!ID.test(entry.id)||
      seen.has(entry.id)||
      Object.keys(entry).some(key=>!["id","offsetMs","sample"].includes(key)))
      fail("TESTLAB_SCENARIO_ENTRY_INVALID");
    seen.add(entry.id);
    if(scenario.mode==="constant-rate"){
      if(entry.offsetMs!==undefined)fail("TESTLAB_SCENARIO_TIMING_INVALID");
    }else{
      if(!Number.isInteger(entry.offsetMs)||entry.offsetMs!<0||
        (index===0&&entry.offsetMs!==0)||
        (index>0&&(entry.offsetMs!-lastOffset<minInterval||
          entry.offsetMs!-lastOffset>3000)))
        fail("TESTLAB_SCENARIO_RATE_CONFLICT");
      lastOffset=entry.offsetMs!;
    }
    const sample=entry.sample;
    if(!sample||typeof sample!=="object"||Array.isArray(sample)||
      typeof sample.runMarkerField!=="string"||
      sample.runId!==undefined||
      Object.keys(sample).some(key=>!PREVIEW_FIELDS.has(key)))
      fail("TESTLAB_SCENARIO_SAMPLE_INVALID");
    try{
      const runId="test_run_00000000000000000000000000000000";
      createSyntheticPreview({...sample,sequence:0,runId},0);
    }catch(error){
      if(error instanceof SyntheticPreviewError)
        fail("TESTLAB_SCENARIO_SAMPLE_INVALID");
      fail("TESTLAB_SCENARIO_INVALID");
    }
  }
  if(scenario.mode==="original-gaps" &&
    (scenario.cycleMs!-lastOffset<minInterval||
      scenario.cycleMs!-lastOffset>3000))
    fail("TESTLAB_SCENARIO_RATE_CONFLICT");
  return {
    contract:"parser-studio.synthetic-scenario.v0.1",
    replayMode:scenario.mode,sampleFamilyCount:scenario.events.length,
    safeToSendToSensor:false,sensorReceivedVerified:false,
    runtimeParsingVerified:false,
  };
}

export function selectScenarioPreview(scenario:ReplayScenario,sequence:number,
  nowMs:number,runId:string,maxRatePerSecond:number):ScenarioPick{
  validateReplayScenario(scenario,maxRatePerSecond);
  if(!Number.isInteger(sequence)||sequence<0||sequence>1e9||
    !RUN.test(runId))fail("TESTLAB_SCENARIO_SEQUENCE_INVALID");
  const index=sequence%scenario.events.length;
  const entry=scenario.events[index]!;
  const nextDelayMs=scenario.mode==="constant-rate"?
    Math.ceil(1000/maxRatePerSecond):
    index===scenario.events.length-1?
      scenario.cycleMs!-entry.offsetMs!:
      scenario.events[index+1]!.offsetMs!-entry.offsetMs!;
  try{
    const preview=createSyntheticPreview({
      ...entry.sample,sequence,runId,
    },nowMs);
    return {sampleId:entry.id,nextDelayMs,preview};
  }catch{
    throw new ScenarioContractError("TESTLAB_SCENARIO_SAMPLE_INVALID");
  }
}
