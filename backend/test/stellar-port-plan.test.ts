import assert from "node:assert/strict";
import test from "node:test";
import {proposeParserPort,validatePortOverride} from "../src/stellar-port-plan.js";

const fullyKnown=()=>{
  return {
    cataloguePorts:[20000,20001,20002,20003],
    tenantLegacyPorts:[20004],
    sensorParserPorts:[20005],
    localReservedPorts:[20006],
    adminReservedPorts:[20007],
    evidence:{catalogueComplete:true,tenantComplete:true,
      sensorBindingsComplete:true,reservationsComplete:true},
  };
};

test("port planner skips built-in/custom/sensor/local/admin collisions across protocols",()=>{
  const result=proposeParserPort(fullyKnown());
  assert.equal(result.recommendedPort,20008);
  assert.equal(result.status,"CANDIDATE_REQUIRES_DEPLOY_RECHECK");
  assert.equal(result.deployableNow,false,"proposing is not an atomic reservation");
  assert.equal(result.verifiedIngestPort,false);
  assert.ok(result.occupiedPorts.includes(20000));
  assert.ok(result.occupiedPorts.includes(20007));
});

test("unknown parser/sensor inventories never imply availability; still show tentative port",()=>{
  const data=fullyKnown();
  data.evidence.sensorBindingsComplete=false;
  const result=proposeParserPort(data);
  assert.equal(result.recommendedPort,20008);
  assert.equal(result.status,"INCOMPLETE_EVIDENCE");
  assert.equal(result.deployableNow,false);
  assert.ok(result.missingEvidence.includes("sensorBindings"));
});

test("user override is editable but occupied/privileged ports are rejected",()=>{
  const evidence=fullyKnown();
  const changed=proposeParserPort(evidence,{requestedPort:23567});
  assert.equal(changed.recommendedPort,23567);
  assert.equal(changed.source,"USER_OVERRIDE");
  assert.throws(()=>validatePortOverride(20004,evidence),/PORT_ALREADY_OCCUPIED/);
  assert.throws(()=>validatePortOverride(80,evidence),/PORT_PRIVILEGED/);
  assert.throws(()=>validatePortOverride(65536,evidence),/PORT_INVALID/);
  assert.throws(()=>validatePortOverride("20008" as any,evidence),/PORT_INVALID/);
});

test("incomplete or malformed inventory fails closed rather than guessing collision-free",()=>{
  const source=fullyKnown();
  source.cataloguePorts.push(NaN);
  assert.throws(()=>proposeParserPort(source),/PORT_EVIDENCE_INVALID/);
  const unknown=fullyKnown() as any;
  unknown.tenantLegacyPorts=[undefined];
  assert.throws(()=>proposeParserPort(unknown),/PORT_EVIDENCE_INVALID/);
  const fullyOccupied=fullyKnown();
  fullyOccupied.cataloguePorts=Array.from({length:5},(_,i)=>20100+i);
  assert.throws(()=>proposeParserPort(fullyOccupied,{rangeStart:20100,rangeEnd:20104}),
    /PORT_NO_CANDIDATE/);
});

test("one chosen listener port must be used for sensor ingestion and generated CONF",()=>{
  const result=proposeParserPort(fullyKnown(),{requestedPort:20333});
  assert.equal(result.recommendedPort,20333);
  assert.equal(result.sensorIngestPort,20333);
  assert.equal(result.verifiedIngestPort,false);
});
