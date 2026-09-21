// Preserve exact source, machine and trace summaries for the statistical diagnostic.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { cpus, platform, arch, release } from 'node:os';
import { join } from 'node:path';
import { root, sourceIdentity, fileSha256 } from '../../scripts/common.mjs';

const source = sourceIdentity();
mkdirSync(join(root, '.reports'), { recursive: true });
const command = ['cargo', 'run', '--manifest-path', 'validation/timing/Cargo.toml', '--release', '--frozen', '--target-dir', 'target/timing', '--', '100000'];
const startedAt = new Date().toISOString();
const result = spawnSync(command[0], command.slice(1), { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
const log = '.reports/timing.log';
writeFileSync(join(root, log), (result.stdout ?? '') + (result.stderr ?? '') + (result.error?.message ?? ''));
const binary = join(root, 'target/timing/release', platform() === 'win32' ? 'post-quantum-timing.exe' : 'post-quantum-timing');
const compiler = spawnSync('rustc', ['--version', '--verbose'], { cwd: root, encoding: 'utf8' });
const sourceAfter = sourceIdentity();
const report = {
  schemaVersion: 1, source, sourceAfter,
  sourceUnchanged: sourceAfter.sourceSha256 === source.sourceSha256,
  startedAt, finishedAt: new Date().toISOString(), command,
  exitCode: result.status, error: result.error?.message ?? null,
  log, logSha256: fileSha256(join(root, log)),
  timingLockSha256: fileSha256(join(root, 'validation/timing/Cargo.lock')),
  compiler: compiler.stdout?.trim(),
  buildEnvironment: { RUSTFLAGS: process.env.RUSTFLAGS ?? null, CARGO_ENCODED_RUSTFLAGS: process.env.CARGO_ENCODED_RUSTFLAGS ?? null, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN ?? null },
  binary, binarySha256: existsSync(binary) ? fileSha256(binary) : null,
  machine: { platform: platform(), arch: arch(), release: release(), cpu: cpus()[0]?.model },
  scope: 'Seven scalar scenarios in a separate release executable using local implementation sources: ChaCha/HMAC/AEAD varied keys, ML-KEM rejection secret z with fixed public key and ciphertext, AEAD and KEM mismatch position, and field multiplication. Equal-sized key pools and same-address symmetric buffers reduce cache confounding. Not a timing measurement of the final Node binary. No proof of constant time; no ML-DSA timing claim. Repeat on controlled physical targets and review compiled code.',
};
report.passed = result.status === 0 && report.sourceUnchanged && !result.error && compiler.status === 0;
writeFileSync(join(root, '.reports/timing.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ passed: report.passed, report: '.reports/timing.json' }));
if (!report.passed) process.exitCode = 1;
