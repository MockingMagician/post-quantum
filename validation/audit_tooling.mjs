// Audit third-party development dependencies only; production has a separate zero-dependency gate.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { root, sourceIdentity, fileSha256, npm } from '../scripts/common.mjs';
mkdirSync(join(root, '.reports'), { recursive: true });
const source = sourceIdentity();
const report = { schemaVersion: 1, source, startedAt: new Date().toISOString(), scope: 'Cargo fuzz workspace and TypeScript validation tooling; not a cryptographic audit.', steps: [] };
const result = spawnSync('cargo', ['audit', '--file', 'fuzz/Cargo.lock', '--deny', 'warnings', '--json'], { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
writeFileSync(join(root, '.reports/tooling-cargo-audit.log'), (result.stdout ?? '') + (result.stderr ?? '') + (result.error?.message ?? ''));
report.steps.push({ command: ['cargo', 'audit', '--file', 'fuzz/Cargo.lock', '--deny', 'warnings', '--json'], exitCode: result.status, lockSha256: fileSha256(join(root, 'fuzz/Cargo.lock')), log: '.reports/tooling-cargo-audit.log', passed: result.status === 0 && !result.error });
try {
  const text = npm(['audit', '--prefix', 'validation/typescript', '--audit-level=low', '--json']);
  writeFileSync(join(root, '.reports/tooling-npm-audit.log'), text + '\n');
  report.steps.push({ command: ['npm', 'audit', '--prefix', 'validation/typescript', '--audit-level=low', '--json'], exitCode: 0, lockSha256: fileSha256(join(root, 'validation/typescript/package-lock.json')), log: '.reports/tooling-npm-audit.log', passed: true });
} catch (error) {
  writeFileSync(join(root, '.reports/tooling-npm-audit.log'), String(error));
  report.steps.push({ command: ['npm', 'audit', '--prefix', 'validation/typescript', '--audit-level=low', '--json'], passed: false, log: '.reports/tooling-npm-audit.log' });
}
for (const step of report.steps) step.logSha256 = fileSha256(join(root, step.log));
report.sourceUnchanged = sourceIdentity().sourceSha256 === source.sourceSha256;
report.finishedAt = new Date().toISOString();
report.passed = report.sourceUnchanged && report.steps.every(step => step.passed);
writeFileSync(join(root, '.reports/tooling-audit.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ passed: report.passed, report: '.reports/tooling-audit.json' }));
if (!report.passed) process.exitCode = 1;
