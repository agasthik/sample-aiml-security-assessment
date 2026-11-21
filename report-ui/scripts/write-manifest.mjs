// Records what the committed bundle was built from. tests/test_report_ui_bundle.py
// recomputes the source hash, so a source change without a rebuild fails CI.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = join(root, '..', 'aiml-security-assessment', 'functions', 'security', 'generate_consolidated_report', 'report_ui');

function files(dir) {
  return readdirSync(dir)
    .flatMap(name => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? files(path) : [path];
    })
    .sort();
}

// Everything `npm run build` reads: the sources, the dependency and build
// configuration (tsc reads tsconfig.json), and this script.
const inputs = [
  ...files(join(root, 'src')),
  ...['package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json', 'scripts/write-manifest.mjs'].map(name => join(root, name)),
];
const hash = createHash('sha256');
for (const path of inputs) {
  hash.update(relative(root, path).split('\\').join('/'));
  hash.update('\0');
  hash.update(readFileSync(path).toString('utf8').replace(/\r\n/g, '\n'));
  hash.update('\0');
}

for (const name of ['report-ui.js', 'report-ui.css']) {
  const text = readFileSync(join(outDir, name), 'utf8');
  if (/<\/(script|style)/i.test(text)) {
    throw new Error(`${name} contains a closing script/style tag and cannot be inlined`);
  }
}

const pkg = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const versions = Object.fromEntries(
  ['@cloudscape-design/components', '@cloudscape-design/global-styles', '@cloudscape-design/collection-hooks', 'react', 'react-dom'].map(name => [
    name,
    pkg.packages[`node_modules/${name}`].version,
  ])
);
writeFileSync(
  join(outDir, 'manifest.json'),
  JSON.stringify({ sourceSha256: hash.digest('hex'), files: ['report-ui.js', 'report-ui.css'], versions }, null, 2) + '\n'
);
console.log('manifest written', versions);
