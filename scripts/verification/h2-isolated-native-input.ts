/** Writes PRIVATE synthetic runner input on stdout for an offline CI container.
 * NEVER log or upload stdout; it includes generated Ruby and synthetic events.
 */
import {buildNativeProjectRunnerInput}
  from '../../backend/src/local-native-project-verifier';
import {prepareH2Synthetic} from '../../backend/test/h2-isolated-native-fixture';

if(process.argv.length!==2)throw Error('H2_FIXED_SYNTHETIC_ONLY');
process.stdout.write(JSON.stringify(buildNativeProjectRunnerInput(prepareH2Synthetic())));
