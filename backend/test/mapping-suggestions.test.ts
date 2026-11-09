import test from "node:test";
import assert from "node:assert/strict";
import {suggestFieldMappings} from "../src/mapping-suggestions.js";

test("known field-name aliases yield deterministic user-review-only IP, action, port mappings",()=>{
  const result=suggestFieldMappings({
    fieldNames:["action","src_ip","destination.ip","dst_port","unknown"],
  });
  assert.deepEqual(result.suggestions.map(x=>[
    x.sourceField,x.proposedDestination,x.type,x.status,
  ]),[
    ["action","action","string","REVIEW_REQUIRED"],
    ["destination.ip","dstip","ip","REVIEW_REQUIRED"],
    ["dst_port","dstport","port","REVIEW_REQUIRED"],
    ["src_ip","srcip","ip","REVIEW_REQUIRED"],
  ]);
  assert.equal(result.autoApplied,false);
  assert.deepEqual(result.unknownFields,["unknown"]);
  assert.equal(result.nativeVerified,false);
});
test("duplicate aliases to the same normalized field are flagged, never auto-selected",()=>{
  const report=suggestFieldMappings({
    fieldNames:["src_ip","source.ip","srcip"],
  });
  assert.equal(report.suggestions.length,3);
  assert.equal(report.suggestions.every(x=>x.status==="DESTINATION_CONFLICT"),true);
  assert.equal(report.autoApplied,false);
});
test("existing mappings cannot be overwritten by generated mapping suggestions",()=>{
  const report=suggestFieldMappings({
    fieldNames:["src_ip","dst_port"],
    existingDestinations:["srcip"],
  });
  assert.equal(report.suggestions[1]?.status,"EXISTING_MAPPING");
  assert.equal(report.suggestions[0]?.status,"REVIEW_REQUIRED");
});
test("prototype keys, malformed paths and raw event values are never allowed in input",()=>{
  for(const field of ["__proto__","constructor","x.__proto__","s\nrcip",
    "THISIS".repeat(100),"../../secret"]){
    assert.throws(()=>suggestFieldMappings({fieldNames:[field]}),
      /MAPPING_INPUT_INVALID/);
  }
  assert.throws(()=>suggestFieldMappings({fieldNames:["srcip"],apiKey:"secret"} as any),
    /MAPPING_INPUT_INVALID/);
});
test("no-value name-only suggestion does not invent mappings for unfamiliar fields",()=>{
  const payload={fieldNames:["raw_private_record","random_blob"]};
  const before=JSON.stringify(payload);
  const r=suggestFieldMappings(payload);
  assert.deepEqual(r.suggestions,[]);
  assert.deepEqual(r.unknownFields,["random_blob","raw_private_record"]);
  assert.equal(JSON.stringify(payload),before);
  assert.equal(r.containsRawValues,false);
});


test("port identity suggestions are derived from canonical policy, including nested SD paths",()=>{
  const direct=suggestFieldMappings({
    fieldNames:["source-port","destination-port","srcport","dstport"],
  });
  assert.deepEqual(direct.unknownFields,[]);
  assert.deepEqual(direct.suggestions.map(x=>[x.sourceField,x.proposedDestination,x.status]),[
    ["destination-port","dstport","DESTINATION_CONFLICT"],
    ["dstport","dstport","DESTINATION_CONFLICT"],
    ["source-port","srcport","DESTINATION_CONFLICT"],
    ["srcport","srcport","DESTINATION_CONFLICT"],
  ]);
  const nested=suggestFieldMappings({
    fieldNames:["Juniper.sd.source-port","Juniper.sd.destination-port"],
  });
  assert.deepEqual(nested.suggestions.map(x=>[x.sourceField,x.proposedDestination,x.status]),[
    ["Juniper.sd.destination-port","dstport","REVIEW_REQUIRED"],
    ["Juniper.sd.source-port","srcport","REVIEW_REQUIRED"],
  ]);
  assert.equal(nested.autoApplied,false);
});

test("ancestor, descendant and NAT provenance never imply safe target assignment",()=>{
  for(const existing of ["srcip.vendor","srcip","srcip.family"]){
    const r=suggestFieldMappings({
      fieldNames:["src_ip"],existingDestinations:[existing],
    });
    assert.equal(r.suggestions[0]?.status,
      existing==="srcip"?"EXISTING_MAPPING":"DESTINATION_CONFLICT");
  }
  const nat=suggestFieldMappings({
    fieldNames:["forwarder.post_nat.source-port","forwarder.translated.destination-port",
      "source-port"],
  });
  assert.deepEqual(nat.unknownFields,[
    "forwarder.post_nat.source-port","forwarder.translated.destination-port",
  ]);
  assert.equal(nat.suggestions[0]?.proposedDestination,"srcport");
});
