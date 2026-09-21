import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const targets = Object.freeze({
  'x86_64-unknown-linux-gnu': { platform: 'linux-x64-gnu', os: 'linux', cpu: 'x64', libc: 'glibc' },
  'aarch64-unknown-linux-gnu': { platform: 'linux-arm64-gnu', os: 'linux', cpu: 'arm64', libc: 'glibc' },
  'x86_64-unknown-linux-musl': { platform: 'linux-x64-musl', os: 'linux', cpu: 'x64', libc: 'musl' },
  'aarch64-unknown-linux-musl': { platform: 'linux-arm64-musl', os: 'linux', cpu: 'arm64', libc: 'musl' },
  'x86_64-apple-darwin': { platform: 'darwin-x64', os: 'darwin', cpu: 'x64' },
  'aarch64-apple-darwin': { platform: 'darwin-arm64', os: 'darwin', cpu: 'arm64' },
  'x86_64-pc-windows-msvc': { platform: 'win32-x64-msvc', os: 'win32', cpu: 'x64' },
});
export function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status}):\n${result.stdout ?? ''}${result.stderr ?? ''}`);
  return result.stdout?.trim();
}
export function npm(args, options = {}) {
  // npm.cmd requires a shell on Windows. Calling npm's JS entry point avoids
  // cmd.exe interpolation and handles temporary directories containing spaces.
  let cli = process.env.npm_execpath;
  if (!cli || !existsSync(cli)) {
    const directory = dirname(process.execPath);
    const candidates = [join(directory, 'node_modules/npm/bin/npm-cli.js'), join(directory, '../lib/node_modules/npm/bin/npm-cli.js')];
    cli = candidates.find(existsSync);
  }
  if (cli) return run(process.execPath, [cli, ...args], options);
  if (process.platform !== 'win32') return run('npm', args, options);
  throw new Error('Run this command through npm so npm_execpath identifies npm-cli.js');
}
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const fileSha256 = (path) => sha256(readFileSync(path));
export function git(command) {
  const result = spawnSync('git', command, { cwd: root, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}
export function sourceIdentity() {
  const inventory = git(['ls-files', '--cached', '--others', '--exclude-standard', '-z']);
  if (inventory === null) throw new Error('Source provenance requires Git and a trusted repository checkout');
  const files = inventory
    .split('\0').filter(Boolean).filter((path) => !path.startsWith('.idea/') && existsSync(join(root, path))).sort();
  const manifest = [...new Set(files)].map((path) => ({ path, sha256: fileSha256(join(root, path)) }));
  return {
    commit: git(['rev-parse', 'HEAD']),
    dirty: Boolean(git(['status', '--porcelain=v1', '--untracked-files=all'])),
    sourceSha256: sha256(JSON.stringify(manifest)),
    files: manifest,
    cargoLockSha256: fileSha256(join(root, 'Cargo.lock')),
    npmLockSha256: fileSha256(join(root, 'package-lock.json')),
  };
}
