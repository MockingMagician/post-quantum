import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import platform from '../lib/platform.cjs';
import { root, targets, run, fileSha256, sourceIdentity } from './common.mjs';

const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== '--target')) throw new Error('Usage: npm run build -- [--target RUST_TARGET]');
const rustc = run('rustc', ['-vV']);
const triple = args[1] ?? rustc.match(/^host: (.+)$/m)?.[1];
const target = targets[triple];
if (!target) throw new Error(`Unsupported Rust target: ${triple}`);
const source = sourceIdentity();
const cargoArgs = ['build', '--manifest-path', 'crates/node/Cargo.toml', '--release', '--frozen', '--no-default-features', '--target', triple, '--target-dir', join(root, 'target')];
// Keep a predictable compiler stack for the local Rust implementation.
const environment = { RUST_MIN_STACK: '33554432', ...process.env };
if (target.libc === 'musl') environment.RUSTFLAGS = `${environment.RUSTFLAGS ?? ''} -C target-feature=-crt-static`.trim();
run('cargo', cargoArgs, { stdio: 'inherit', env: environment });
if (sourceIdentity().sourceSha256 !== source.sourceSha256) throw new Error('Source changed during compilation; rebuild from a stable checkout');
const library = target.os === 'win32' ? 'post_quantum.dll' : target.os === 'darwin' ? 'libpost_quantum.dylib' : 'libpost_quantum.so';
mkdirSync(join(root, 'native'), { recursive: true });
const binary = `post_quantum.${target.platform}.node`;
const output = join(root, 'native', binary);
copyFileSync(join(root, 'target', triple, 'release', library), output);
// Loading the real binary catches incomplete initialization and any accidentally
// enabled validation hooks, including feature cfgs supplied through RUSTFLAGS.
const nativeLoadChecked = platform() === target.platform;
if (nativeLoadChecked) run(process.execPath, ['-e', `require(${JSON.stringify(join(root, 'index.cjs'))})`]);
const provenance = {
  schemaVersion: 1, target: triple, platform: target.platform,
  binary, sha256: fileSha256(output), source,
  toolchain: { rustc, cargo: run('cargo', ['--version']), node: process.version },
  command: ['cargo', ...cargoArgs],
  rustflags: environment.RUSTFLAGS ?? null,
  rustMinStack: environment.RUST_MIN_STACK,
  nativeLoadChecked,
  github: process.env.GITHUB_RUN_ID ? { repository: process.env.GITHUB_REPOSITORY, runId: process.env.GITHUB_RUN_ID, runAttempt: process.env.GITHUB_RUN_ATTEMPT, sha: process.env.GITHUB_SHA } : null,
};
writeFileSync(`${output}.build.json`, `${JSON.stringify(provenance, null, 2)}\n`);
console.log(`Built ${binary} (${provenance.sha256})`);
