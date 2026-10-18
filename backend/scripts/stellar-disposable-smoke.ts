/** Stdout fixed public synthetic POC null-sink CONF only; NO API requests. */
import {makeDisposablePocTestPair,makeLegacyUploadPlan,
  requireDisposablePocWrite} from "../src/stellar-legacy-plan.js";
import {sampleProject} from "../test/fixture.js";

const fixture=sampleProject();
fixture.slug="ps_api_crud_test_a1b2c3";
fixture.receiver.port=7891;
fixture.receiver.bindAddress="127.0.0.1";
const pair=makeDisposablePocTestPair(fixture);
const plan=makeLegacyUploadPlan(pair,"synthetic_tenant","1.0.0");
requireDisposablePocWrite(plan);
const conf=plan.multipartFiles()[1];
if(conf?.filename!=="customized_ps_api_crud_test_a1b2c3.conf")
  throw new Error("POC synthetic test artifact contract changed");
process.stdout.write(conf.body.toString("utf8"));
