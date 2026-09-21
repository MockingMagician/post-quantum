// Linux validation tooling only; no sanitizer or test hook enters package artifacts.
import { copyFileSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { root, fileSha256, sourceIdentity } from '../scripts/common.mjs';

if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('This gate currently supports Linux x64 GNU only');
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--node')) throw new Error('Usage: node validation/ffi_asan.mjs [--node /path/to/node22-or-node24]');
const node = args[1] ?? process.execPath;
const toolchain = 'nightly-2026-09-21';
const target = 'x86_64-unknown-linux-gnu';
const directory = join(root, 'target', 'ffi-asan');
const stage = join(directory, 'production');
const source = sourceIdentity();
const steps = [];
const report = { schemaVersion: 1, source, passed: false, steps,
  scope: 'AddressSanitizer instruments the local Rust binding/core/platform. Node/V8 and the precompiled Rust standard library are not instrumented; passing this gate is not a proof of absence of memory bugs.' };
function execute(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, ...options });
  const step = { command: [command, ...args], exitCode: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr };
  steps.push(step);
  if (result.error) throw result.error;
  return step;
}
function success(command, args, options) {
  const step = execute(command, args, options);
  if (step.exitCode !== 0) throw new Error(`${command} failed; see .reports/ffi-asan.json`);
  return step.stdout.trim();
}
mkdirSync(directory, { recursive: true });
try {
  report.node = success(node, ['--version']);
  if (!/^v(22|24)\./.test(report.node)) throw new Error('Use a supported Node 22 or 24 executable for the sanitizer gate');
  report.rustc = success('rustc', [`+${toolchain}`, '-vV']);
  // GCC's shared ASan runtime supplies the stable __asan ABI to the instrumented
  // addon before Node starts. Record the actual runtime, and verify it with an
  // intentionally invalid, separate addon before trusting any successful test.
  const runtime = realpathSync(success('gcc', ['-print-file-name=libasan.so']));
  report.runtime = { path: runtime, sha256: fileSha256(runtime), gcc: success('gcc', ['--version']) };
  const runtimeEnv = { ...process.env, LD_PRELOAD: runtime,
    ASAN_OPTIONS: 'detect_leaks=1:detect_stack_use_after_return=1:abort_on_error=1:disable_coredump=1' };
  delete runtimeEnv.LSAN_OPTIONS;
  report.asanOptions = runtimeEnv.ASAN_OPTIONS;
  // A host-runtime leak must remain a failure; never mask it with suppressions
  // or claim that a failing Node baseline validates this addon.
  success(node, ['-e', 'void 0'], { env: runtimeEnv });
  report.hostBaselinePassed = true;
  const rustflags = '-Zsanitizer=address -C force-frame-pointers=yes -C debuginfo=1';
  const buildEnv = { ...process.env, RUSTFLAGS: rustflags, CARGO_ENCODED_RUSTFLAGS: '' };
  delete buildEnv.CARGO_ENCODED_RUSTFLAGS;
  report.rustflags = rustflags;
  const probe = join(directory, 'negative_control.rs');
  const probeBinary = join(directory, 'negative_control.node');
  writeFileSync(probe, `// Deliberately invalid validation control, never production code.
use std::ffi::c_void;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(_: *mut c_void, exports: *mut c_void) -> *mut c_void {
    let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
    let memory = unsafe { std::alloc::alloc(layout) };
    if memory.is_null() { std::alloc::handle_alloc_error(layout); }
    unsafe { std::ptr::write_volatile(memory.add(std::hint::black_box(16)), 7); }
    unsafe { std::alloc::dealloc(memory, layout); }
    exports
}
`);
  success('rustc', [`+${toolchain}`, '--edition=2024', '--crate-type=cdylib', '--target', target,
    '-Zsanitizer=address', '-Cforce-frame-pointers=yes', '-Cdebuginfo=1', probe, '-o', probeBinary]);
  const control = execute(node, ['-e', `require(${JSON.stringify(probeBinary)})`], { env: runtimeEnv });
  control.expectedFailure = true;
  if (control.exitCode === 0 || !/ERROR: AddressSanitizer: heap-buffer-overflow/.test(control.stderr)) {
    throw new Error('ASan negative control did not report its known heap overflow');
  }
  const cargo = [`+${toolchain}`, 'build', '-p', 'post-quantum-node', '--release', '--frozen', '--no-default-features', '--target', target, '--target-dir', directory];
  success('cargo', cargo, { env: buildEnv });
  for (const file of ['index.cjs', 'index.mjs', 'lib/platform.cjs', 'tests/api.test.cjs', 'tests/native-boundary.test.cjs', 'tests/ffi-lifecycle.test.cjs']) {
    mkdirSync(dirname(join(stage, file)), { recursive: true });
    copyFileSync(join(root, file), join(stage, file));
  }
  mkdirSync(join(stage, 'native'), { recursive: true });
  const library = join(directory, target, 'release', 'libpost_quantum.so');
  const production = join(stage, 'native', 'post_quantum.linux-x64-gnu.node');
  copyFileSync(library, production);
  report.productionSha256 = fileSha256(production);
  success(node, ['--test', '--test-concurrency=1', ...['api', 'native-boundary', 'ffi-lifecycle'].map(name => join(stage, 'tests', `${name}.test.cjs`))], { env: runtimeEnv });
  success('cargo', [...cargo, '--features', 'validation-hooks'], { env: buildEnv });
  const validation = join(directory, 'validation.node');
  copyFileSync(library, validation);
  report.validationSha256 = fileSha256(validation);
  success(node, ['--expose-gc', 'tests/ffi-faults.cjs', validation], { env: runtimeEnv });
  report.sourceUnchanged = sourceIdentity().sourceSha256 === source.sourceSha256;
  if (!report.sourceUnchanged) throw new Error('Source changed during the sanitizer gate');
  report.passed = true;
} catch (error) {
  report.error = error.message;
  process.exitCode = 1;
} finally {
  mkdirSync(join(root, '.reports'), { recursive: true });
  writeFileSync(join(root, '.reports', 'ffi-asan.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ passed: report.passed, report: '.reports/ffi-asan.json', ...(report.error ? { error: report.error } : {}) }));
}
