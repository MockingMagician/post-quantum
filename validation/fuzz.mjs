// Bounded ASan campaigns against the local implementation, with exact provenance.
import { spawnSync } from 'node:child_process';
import { closeSync, mkdirSync, openSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, sourceIdentity, fileSha256 } from '../scripts/common.mjs';

const directory = join(root, 'artifacts', 'validation');
mkdirSync(directory, { recursive: true });
const nightly = 'nightly-2026-09-21';
const lockfiles = () => Object.fromEntries(['Cargo.lock', 'fuzz/Cargo.lock'].map(path => [path, fileSha256(join(root, path))]));
const report = {
  schemaVersion: 1, startedAt: new Date().toISOString(), source: sourceIdentity(),
  lockfilesBefore: lockfiles(), toolVersions: {}, campaigns: [],
  scope: 'Bounded libFuzzer/AddressSanitizer campaigns; absence of findings is not exhaustive correctness or memory-safety proof.',
};
let passed = true;
try {
  for (const [name, args] of [
    ['rustc', ['rustc', `+${nightly}`, '--version', '--verbose']],
    ['cargo-fuzz', ['cargo', `+${nightly}`, 'fuzz', '--version']],
  ]) {
    const result = spawnSync(args[0], args.slice(1), { cwd: root, encoding: 'utf8' });
    if (result.status !== 0 || result.error) throw new Error(`Unable to identify ${name}: ${result.stderr ?? result.error}`);
    report.toolVersions[name] = result.stdout.trim();
  }
  if (!report.toolVersions['cargo-fuzz'].includes('0.13.2')) throw new Error('Expected pinned cargo-fuzz 0.13.2');
  const seed = spawnSync('python3', ['validation/seed_fuzz.py'], { cwd: root, encoding: 'utf8' });
  if (seed.status !== 0 || seed.error) throw new Error(`Unable to prepare boundary corpus: ${seed.stderr ?? seed.error}`);
  for (const [target, runs, maxLength, randomSeed] of [
    ['byte_inputs', 100000, 20000, 203204],
    ['operations', 200, 4096, 204203],
    ['primitives', 100000, 4096, 8439203],
  ]) {
    const command = ['cargo', `+${nightly}`, 'fuzz', 'run', target, '--', `-runs=${runs}`, `-seed=${randomSeed}`, `-max_len=${maxLength}`, '-rss_limit_mb=512', '-timeout=10'];
    const log = `artifacts/validation/fuzz-${target}.log`;
    const handle = openSync(join(root, log), 'w');
    console.log(`Fuzz: ${target}, ${runs} runs`);
    const startedAt = new Date().toISOString();
    let result;
    try { result = spawnSync(command[0], command.slice(1), { cwd: root, stdio: ['ignore', handle, handle] }); }
    finally { closeSync(handle); }
    const success = result.status === 0 && !result.error;
    report.campaigns.push({ target, command, startedAt, finishedAt: new Date().toISOString(), exitCode: result.status, signal: result.signal, error: result.error?.message ?? null, success, log, logSha256: fileSha256(join(root, log)) });
    if (!success) { passed = false; break; }
  }
} catch (error) {
  report.error = String(error);
  passed = false;
}
report.sourceAfter = sourceIdentity();
report.sourceUnchanged = report.source.sourceSha256 === report.sourceAfter.sourceSha256;
report.lockfilesAfter = lockfiles();
report.lockfilesUnchanged = JSON.stringify(report.lockfilesBefore) === JSON.stringify(report.lockfilesAfter);
report.finishedAt = new Date().toISOString();
report.passed = passed && report.campaigns.length === 3 && report.sourceUnchanged && report.lockfilesUnchanged;
writeFileSync(join(directory, 'fuzz-report.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ passed: report.passed, sourceUnchanged: report.sourceUnchanged, report: 'artifacts/validation/fuzz-report.json' }));
if (!report.passed) process.exitCode = 1;
