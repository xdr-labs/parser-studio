// Compiles EVERY enumerated compiler variant (backend/test/compiler-variants.ts)
// with the real compilePair and emits one compressed private payload for the
// offline Ruby matrix runner. Synthetic fixtures only; nothing is written to
// disk and no network is used. The payload is a transport for the generated
// fragments, not a place where expectations are stored.
import { deflateSync } from 'node:zlib';
import { compilePair } from '../../backend/src/index.js';
import { compilerVariants } from '../../backend/test/compiler-variants.js';

const variants = compilerVariants().map(({ id, project }) => {
  const pair = compilePair(project);
  const ruby = pair.files.find(file => !file.name.endsWith('.conf'));
  if (!ruby) throw new Error('RUBY_VARIANT_MATRIX_FRAGMENT_MISSING ' + id);
  return {
    id,
    sha256: ruby.sha256,
    compressedRuby: deflateSync(Buffer.from(ruby.content, 'utf8')).toString('base64'),
  };
});
if (new Set(variants.map(v => v.id)).size !== variants.length) throw new Error('RUBY_VARIANT_MATRIX_DUPLICATE_ID');

const input = JSON.stringify({ contract: 'parser-studio.variant-matrix.v1', count: variants.length, variants });
if (process.argv[2] === '--private-payload') {
  process.stdout.write(deflateSync(Buffer.from(input, 'utf8')).toString('base64') + '\n');
} else {
  process.stdout.write(JSON.stringify({ contract: 'parser-studio.variant-matrix.v1', count: variants.length, ids: variants.map(v => v.id) }, null, 2) + '\n');
}
