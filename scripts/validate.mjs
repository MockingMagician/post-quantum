import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, sourceIdentity } from './common.mjs';

const directory = join(root, '.reports');
mkdirSync(directory, { recursive: true });
const source = sourceIdentity();
const steps = [
  ['production-isolation', process.execPath, ['validation/production_graph.mjs']],
  ['format', 'cargo', ['fmt', '--all', '--', '--check']],
  ['clippy', 'cargo', ['clippy', '--workspace', '--all-targets', '--frozen', '--', '-D', 'warnings']],
  ['rust-tests', 'cargo', ['test', '--workspace', '--frozen']],
  ['converted-fixture-integrity', 'python3', ['validation/prepare_vectors.py', '--check']],
  ['primitive-fixture-integrity', 'python3', ['validation/fetch_primitives.py', '--check']],
  ['nist-fixture-integrity', 'python3', ['validation/fetch_acvp.py', '--check']],
  ['typescript', process.execPath, ['validation/typescript/node_modules/typescript/bin/tsc', '-p', 'validation/typescript/tsconfig.json', '--noEmit']],
  ['build', process.execPath, ['scripts/build.mjs']],
  ['node-tests', process.execPath, ['--test', ...readdirSync(join(root, 'tests')).filter(name => name.endsWith('.test.cjs')).sort().map(name => `tests/${name}`)]],
  ['ffi-failures', process.execPath, ['validation/ffi_failures.mjs']],
  ['interop-bridge', 'cargo', ['build', '-p', 'post-quantum-core', '--example', 'interop', '--frozen']],
  ['symmetric-reference-integrity', 'python3', ['validation/symmetric_reference.py', '--check']],
  ['independent-interop', 'python3', ['validation/openssl_interop.py', '--node']],
  ['tooling-audit', process.execPath, ['validation/audit_tooling.mjs']],
  ['package', process.execPath, ['scripts/package.mjs']],
  ['package-install', process.execPath, ['scripts/test-package.mjs']],
];
const report = { schemaVersion: 1, startedAt: new Date().toISOString(), source, node: process.version, steps: [] };
let failed = false;
for (const [name, command, args] of steps) {
  console.log(`Validation: ${name}`);
  const start = Date.now();
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', env: { ...process.env, RUST_MIN_STACK: process.env.RUST_MIN_STACK ?? '33554432' }, maxBuffer: 32 * 1024 * 1024 });
  const log = `.reports/${name}.log`;
  writeFileSync(join(root, log), `${result.stdout ?? ''}${result.stderr ?? ''}${result.error ? `\n${result.error}` : ''}`);
  report.steps.push({ name, command: [command, ...args], exitCode: result.status, durationMs: Date.now() - start, log, success: result.status === 0 && !result.error });
  if (result.status !== 0 || result.error) {
    failed = true; console.error(`Failed: ${name}; see ${log}`);
    break;
  }
}
report.finishedAt = new Date().toISOString();
report.sourceUnchanged = sourceIdentity().sourceSha256 === source.sourceSha256;
report.success = !failed && report.sourceUnchanged;
report.scope = 'Current host only. Fuzz campaigns and full Node22/24 platform matrix are separate gates.';
writeFileSync(join(directory, 'validation.json'), `${JSON.stringify(report, null, 2)}\n`);
if (!report.success) process.exitCode = 1;
console.log(`Validation ${report.success ? 'passed' : 'incomplete'}; report: .reports/validation.json`);
