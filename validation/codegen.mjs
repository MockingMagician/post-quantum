// Reproducible, pre-final-link release assembly for a bounded human review.
// This is neither a constant-time proof nor inspection of the final Node image.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { root, sourceIdentity, fileSha256 } from '../scripts/common.mjs';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--target') throw new Error('Usage: node validation/codegen.mjs --target RUST_TARGET');
const target = args[1];
if (!['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'].includes(target)) throw new Error('The documented review covers Linux x64 and ARM64');
const directory = join(root, '.reports', 'codegen', target);
mkdirSync(directory, { recursive: true });
const scratch = mkdtempSync(join(tmpdir(), 'pq-codegen-'));
const source = sourceIdentity();
const relevant = identity => identity.files.filter(file => ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'].includes(file.path) || /^crates\/(core|platform)\//.test(file.path));
const report = { schemaVersion: 1, target, startedAt: new Date().toISOString(), source, commands: [], files: [], scope: 'Optimized Rust core/platform rlib assembly before final Node ThinLTO/link. Instruction screening plus manual review; not a constant-time proof.' };
try {
  for (const pkg of ['post-quantum-platform', 'post-quantum-core']) {
    const command = ['rustc', '-p', pkg, '--lib', '--release', '--frozen', '--target', target, '--target-dir', scratch, '--', '--emit=asm'];
    const result = spawnSync('cargo', command, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    const log = join(directory, `${pkg}.log`);
    writeFileSync(log, (result.stdout ?? '') + (result.stderr ?? '') + (result.error?.message ?? ''));
    report.commands.push({ command: ['cargo', ...command], exitCode: result.status, log, logSha256: fileSha256(log) });
    if (result.status !== 0 || result.error) throw new Error(`Assembly generation failed: ${pkg}`);
    const dependencies = join(scratch, target, 'release', 'deps');
    const prefix = pkg.replaceAll('-', '_') + '-';
    const files = readdirSync(dependencies).filter(name => name.startsWith(prefix) && name.endsWith('.s'));
    if (files.length !== 1) throw new Error(`Expected one assembly source for ${pkg}, got ${files.length}`);
    const destination = join(directory, `${pkg}.s`);
    copyFileSync(join(dependencies, files[0]), destination);
    const assembly = readFileSync(destination, 'utf8');
    const divisionInstructions = assembly.split('\n').filter(line => /^\s+(?:idiv[qlwb]?|div[qlwb]?|sdiv|udiv)\s/.test(line));
    const comparisonCalls = assembly.split('\n').filter(line => /\b(?:callq?|bl)\b.*\b(?:memcmp|bcmp)\b/.test(line));
    const opaqueReferences = assembly.split('\n').filter(line => line.includes('opaque_u8')).length;
    report.files.push({ package: pkg, path: destination, sha256: fileSha256(destination), divisionInstructions, comparisonCalls, opaqueReferences });
    if (pkg === 'post-quantum-core' && (divisionInstructions.length || comparisonCalls.length || !opaqueReferences)) {
      throw new Error('Generated core code changed a screened instruction pattern; manual investigation required');
    }
  }
  report.sourceAfter = sourceIdentity();
  report.compilerInputsUnchanged = JSON.stringify(relevant(source)) === JSON.stringify(relevant(report.sourceAfter));
  if (!report.compilerInputsUnchanged) throw new Error('Compiler inputs changed during assembly capture');
  report.passedInstructionScreening = true;
} catch (error) {
  report.error = String(error);
  report.passedInstructionScreening = false;
  process.exitCode = 1;
} finally {
  report.finishedAt = new Date().toISOString();
  report.toolchain = spawnSync('rustc', ['--version', '--verbose'], { cwd: root, encoding: 'utf8' }).stdout?.trim();
  writeFileSync(join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  rmSync(scratch, { recursive: true, force: true });
  console.log(JSON.stringify({ report: join(directory, 'report.json'), passedInstructionScreening: report.passedInstructionScreening, error: report.error ?? null }));
}
