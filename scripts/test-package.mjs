import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import platform from '../lib/platform.cjs';
import { root, run, npm, fileSha256 } from './common.mjs';

const selected = platform();
const destination = join(root, 'dist', selected);
const manifest = JSON.parse(readFileSync(join(destination, 'manifest.json')));
if (manifest.platform !== selected) throw new Error('Archive platform does not match running Node.js');
for (const archive of manifest.archives) {
  if (fileSha256(join(destination, archive.filename)) !== archive.sha256) throw new Error(`Archive checksum mismatch: ${archive.filename}`);
}
const temporary = mkdtempSync(join(tmpdir(), 'post-quantum-package-'));
try {
  writeFileSync(join(temporary, 'package.json'), JSON.stringify({ name: 'archive-install-check', version: '1.0.0', private: true }));
  npm(['install', '--ignore-scripts', '--no-audit', '--no-fund', '--offline', '--package-lock=false', ...manifest.archives.map(({ filename }) => join(destination, filename))], { cwd: temporary });
  const installedNative = createRequire(join(temporary, 'package.json')).resolve(`post-quantum-${selected}`);
  if (fileSha256(installedNative) !== manifest.build.sha256) throw new Error('Installed native binary differs from the recorded build');
  const smoke = join(temporary, 'smoke.cjs');
  copyFileSync(join(root, 'scripts/package-smoke.cjs'), smoke);
  const output = run(process.execPath, [smoke, temporary], { cwd: temporary });
  const result = JSON.parse(output);
  const record = {
    schemaVersion: 1, platform: selected, node: process.version, passed: result.passed,
    nativeSha256: manifest.build.sha256,
    archives: manifest.archives.map(({ filename, sha256 }) => ({ filename, sha256 })),
    tests: result.tests,
  };
  writeFileSync(join(destination, `runtime-node${process.versions.node.split('.')[0]}.json`), `${JSON.stringify(record, null, 2)}\n`);
  console.log(`Packed archives passed on ${selected}, Node.js ${process.version}`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
