import {spawnSync} from 'node:child_process';

const defaultProbe=()=>spawnSync('ruby',['-v'],{encoding:'utf8',timeout:10000});

/**
 * Many native tests skip themselves when Ruby is absent. In native CI mode
 * (PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED=1) that would turn a missing
 * runtime into a green run, so the runner refuses to start instead. An optional
 * PARSER_STUDIO_EXPECT_RUBY pins the interpreter version (for example 2.4.9 when
 * a shim runs the pinned target image).
 */
export function rubyRequirementProblem(env,probe=defaultProbe){
  if(env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED!=='1')return undefined;
  const result=probe();
  if(result.status!==0)return 'RUBY_REQUIRED_BUT_MISSING: native conformance is required but `ruby -v` failed';
  const expected=env.PARSER_STUDIO_EXPECT_RUBY;
  if(expected&&!String(result.stdout).startsWith('ruby '+expected))
    return 'RUBY_VERSION_MISMATCH: expected ruby '+expected+' but got '+String(result.stdout).trim();
  return undefined;
}
