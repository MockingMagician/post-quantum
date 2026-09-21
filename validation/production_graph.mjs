// Production dependency and clean-cache/network-isolation gate. No npm dependencies.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { root, sourceIdentity, fileSha256 } from '../scripts/common.mjs';

const before = sourceIdentity();
const directory = join(root, '.reports');
mkdirSync(directory, { recursive: true });
const scratch = mkdtempSync(join(tmpdir(), 'pq-offline-build-'));
const cargoHome = join(scratch, 'cargo-home');
const targetDir = join(scratch, 'target');
mkdirSync(cargoHome);
const report = { schemaVersion: 1, startedAt: new Date().toISOString(), sourceBefore: before, passed: false, steps: [], trustedBase: 'Pinned Rust toolchain including std, system linker/SDK, OS and Node-API host; no third-party Cargo packages.' };
function run(name, command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, ...options });
  const log = `.reports/production-${name}.log`;
  writeFileSync(join(root, log), (result.stdout ?? '') + (result.stderr ?? '') + (result.error?.message ?? ''));
  report.steps.push({ name, command: [command, ...args], exitCode: result.status, log, logSha256: fileSha256(join(root, log)) });
  if (result.status !== 0 || result.error) throw new Error(`${name} failed; see ${log}`);
  return result.stdout;
}
try {
  const cargo = run('cargo-path', 'rustup', ['which', 'cargo']).trim();
  const rustc = run('rustc-path', 'rustup', ['which', 'rustc']).trim();
  report.toolchain = run('rustc-version', rustc, ['--version', '--verbose']).trim();
  const env = { ...process.env, CARGO_HOME: cargoHome, CARGO_TARGET_DIR: targetDir, CARGO_NET_OFFLINE: 'true', RUSTC: rustc };
  report.cacheEmptyBefore = readdirSync(cargoHome).length === 0;
  if (!report.cacheEmptyBefore) throw new Error('Cargo cache must start empty');
  if (process.platform !== 'linux') throw new Error('Network namespace gate requires Linux; run this gate in the prepared Linux job');
  const isolated = (name, args) => run(name, 'unshare', ['--user', '--map-root-user', '--net', cargo, ...args], { env });
  report.networkNamespace = run('network-namespace', 'unshare', ['--user', '--map-root-user', '--net', 'readlink', '/proc/self/ns/net']).trim();
  report.hostNetworkNamespace = run('host-network-namespace', 'readlink', ['/proc/self/ns/net']).trim();
  if (report.networkNamespace === report.hostNetworkNamespace) throw new Error('Network namespace isolation not established');
  const metadata = JSON.parse(isolated('metadata', ['metadata', '--format-version', '1', '--frozen']));
  const allowed = new Set(['crates/core/Cargo.toml', 'crates/node/Cargo.toml', 'crates/platform/Cargo.toml'].map(path => resolve(root, path)));
  for (const pkg of metadata.packages) {
    if (pkg.source !== null || !allowed.has(resolve(pkg.manifest_path))) throw new Error(`Non-local or unapproved production crate: ${pkg.name}`);
    for (const dep of pkg.dependencies) {
      if (!dep.path || dep.source !== null || !allowed.has(join(resolve(dep.path), 'Cargo.toml'))) throw new Error(`Unapproved dependency ${pkg.name} -> ${dep.name}`);
    }
  }
  if (metadata.packages.length !== 3) throw new Error('Production graph must consist of core, platform and Node crates only');
  report.packages = metadata.packages.map(pkg => ({ name: pkg.name, id: pkg.id, manifest: pkg.manifest_path, dependencies: pkg.dependencies }));
  isolated('build', ['build', '--workspace', '--release', '--frozen']);
  const binary = join(targetDir, 'release/libpost_quantum.so');
  report.binarySha256 = fileSha256(binary);
  const dynamic = run('dynamic-imports', 'readelf', ['-d', binary]);
  if (/\(NEEDED\).*\b(libcrypto|libssl|libsodium|liboqs|libmbedcrypto|libwolfssl)/i.test(dynamic)) throw new Error('Unexpected cryptography library import');
  const symbols = run('undefined-symbols', 'nm', ['-D', '--undefined-only', binary]);
  if (/\b(EVP_|OPENSSL_|sodium_|OQS_)/.test(symbols)) throw new Error('Unexpected external cryptographic symbol');
  report.passed = true;
} catch (error) {
  report.error = String(error);
  process.exitCode = 1;
} finally {
  report.sourceAfter = sourceIdentity();
  report.sourceUnchanged = report.sourceAfter.sourceSha256 === before.sourceSha256;
  report.passed &&= report.sourceUnchanged;
  if (!report.passed) process.exitCode = 1;
  report.finishedAt = new Date().toISOString();
  writeFileSync(join(directory, 'production-isolation.json'), JSON.stringify(report, null, 2) + '\n');
  rmSync(scratch, { recursive: true, force: true });
  console.log(JSON.stringify({ passed: report.passed, sourceUnchanged: report.sourceUnchanged, error: report.error ?? null, report: '.reports/production-isolation.json' }));
}
