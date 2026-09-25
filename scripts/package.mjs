import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import platform from '../lib/platform.cjs';
import { root, targets, npm, fileSha256, sourceIdentity } from './common.mjs';

const requested = process.argv.slice(2);
if (requested.length > 1) throw new Error('Usage: npm run pack:artifacts -- [PLATFORM]');
const selected = requested[0] ?? platform();
const target = Object.values(targets).find((item) => item.platform === selected);
if (!target) throw new Error(`Unsupported platform: ${selected}`);
const manifest = JSON.parse(readFileSync(join(root, 'package.json')));
if (manifest.private !== true) throw new Error('Public publication is outside this project stage; keep private=true');
for (const item of Object.values(targets)) {
  if (manifest.optionalDependencies?.[`${manifest.name}-${item.platform}`] !== manifest.version) throw new Error(`Missing exact optional dependency for ${item.platform}`);
}
for (const path of ['index.cjs', 'index.mjs', 'index.d.ts', 'README.md', 'LICENSE-MIT', 'LICENSE-APACHE', 'SECURITY.md', 'Cargo.lock', 'package-lock.json']) {
  if (!existsSync(join(root, path))) throw new Error(`Missing required packaging input: ${path}`);
}
const binary = `post_quantum.${selected}.node`;
const sourceBinary = join(root, 'native', binary);
const build = JSON.parse(readFileSync(`${sourceBinary}.build.json`));
if (build.platform !== selected || build.sha256 !== fileSha256(sourceBinary)) throw new Error('Native binary does not match its build record');
if (build.source.sourceSha256 !== sourceIdentity().sourceSha256) throw new Error('Source changed after the native build; run npm run build again before packaging');
const destination = join(root, 'dist', selected);
const packageDirectory = join(destination, 'platform-package');
mkdirSync(packageDirectory, { recursive: true });
copyFileSync(sourceBinary, join(packageDirectory, binary));
copyFileSync(`${sourceBinary}.build.json`, join(packageDirectory, 'BUILD.json'));
copyFileSync(join(root, 'LICENSE-MIT'), join(packageDirectory, 'LICENSE-MIT'));
copyFileSync(join(root, 'LICENSE-APACHE'), join(packageDirectory, 'LICENSE-APACHE'));
const nativeManifest = {
  name: `${manifest.name}-${selected}`, version: manifest.version, private: true,
  description: `Native ${selected} binding for ${manifest.name}`,
  license: manifest.license,
  main: binary, files: [binary, 'BUILD.json', 'LICENSE-MIT', 'LICENSE-APACHE'],
  os: [target.os], cpu: [target.cpu], ...(target.libc ? { libc: [target.libc] } : {}),
  engines: manifest.engines,
};
writeFileSync(join(packageDirectory, 'package.json'), `${JSON.stringify(nativeManifest, null, 2)}\n`);
const [nativeArchive] = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', destination], { cwd: packageDirectory }));
const [rootArchive] = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', destination]));
if (rootArchive.files.some((file) => file.path.endsWith('.node'))) throw new Error('Root package unexpectedly contains a native binary');
if (nativeArchive.files.filter((file) => file.path.endsWith('.node')).map((file) => file.path).join() !== binary) throw new Error('Platform package has an unexpected native file');
if (build.source.sourceSha256 !== sourceIdentity().sourceSha256) throw new Error('Source changed during packaging; rebuild before trying again');
const record = {
  schemaVersion: 1, platform: selected, version: manifest.version, build,
  archives: [rootArchive, nativeArchive].map(({ filename, integrity, files }) => ({ filename, sha256: fileSha256(join(destination, filename)), integrity, files: files.map(({ path }) => path) })),
};
writeFileSync(join(destination, 'manifest.json'), `${JSON.stringify(record, null, 2)}\n`);
copyFileSync(join(root, 'Cargo.lock'), join(destination, 'Cargo.lock'));
copyFileSync(join(root, 'package-lock.json'), join(destination, 'package-lock.json'));
writeFileSync(join(destination, 'SHA256SUMS'), `${record.archives.map(({ sha256, filename }) => `${sha256}  ${filename}`).join('\n')}\n`);
console.log(`Prepared archives in ${destination}`);
