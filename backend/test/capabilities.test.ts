import assert from "node:assert/strict";
import test from "node:test";
import projectSchema from "../schema/parser-project.v0.1.schema.json" with { type: "json" };
import { BACKEND_CAPABILITIES } from "../src/index.js";

test("capability response matches reviewed schema, not future unimplemented transports or parsers", () => {
  const { authoring, verification, limits } = BACKEND_CAPABILITIES;
  assert.deepEqual(authoring.receiverProtocols,
    projectSchema.properties.receiver.properties.protocols.items.enum);
  assert.deepEqual(authoring.extractionFormats,
    projectSchema.properties.extraction.properties.format.enum);
  assert.equal(authoring.httpReceiver, false);
  assert.equal(authoring.multipleDistinctReceiverPorts, false);
  assert.equal(authoring.multiline, false);
  assert.equal(authoring.arbitraryRuby, false);
  assert.equal(authoring.formatCoverage, "reviewed-bounded-subset");
  assert.equal(authoring.genericStructuralGrammar, "GENERIC_STRUCTURAL_ULTRA_COMPILER_V9");
  assert.equal(authoring.rfc5424AdjacentStructuredDataSubset, true);
  assert.equal(authoring.rfc5424StructuredDataMaxBytes, 1024);
  assert.deepEqual(authoring.rfc5424BodyFormats,
    projectSchema.properties.extraction.properties.syslogBodyFormat.enum);
  assert.equal(authoring.leefHexSeparatorSubset, true);
  assert.equal(verification.liveListenerVerified, false);
  assert.equal(verification.proprietaryLoaderVerified, false);
  assert.equal(verification.targetImportVerified, false);
  assert.equal(verification.engineVerified, false);
  assert.equal(limits.maxProjectBodyBytes, 256*1024);
  assert.equal(limits.maxInspectBodyBytes, 2*1024*1024);
});