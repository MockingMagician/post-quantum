import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, targets, fileSha256, sourceIdentity } from './common.mjs';

const outcomes = [];
const source = sourceIdentity();
const packageManifest = JSON.parse(readFileSync(join(root, 'package.json')));
for (const { platform } of Object.values(targets)) {
  const directory = join(root, 'dist', platform);
  const manifestPath = join(directory, 'manifest.json');
  if (!existsSync(manifestPath)) throw new Error(`Missing platform artifacts: ${platform}`);
  const manifest = JSON.parse(readFileSync(manifestPath));
  if (manifest.platform !== platform || manifest.version !== packageManifest.version) throw new Error(`Manifest target/version mismatch: ${platform}`);
  if (manifest.build.source.dirty || !manifest.build.source.commit) throw new Error(`Release needs a clean committed source build: ${platform}`);
  if (manifest.build.source.sourceSha256 !== source.sourceSha256 || manifest.build.source.cargoLockSha256 !== source.cargoLockSha256 || manifest.build.source.npmLockSha256 !== source.npmLockSha256) throw new Error(`Artifact source or dependency lock mismatch: ${platform}`);
  if (process.env.GITHUB_SHA && manifest.build.source.commit !== process.env.GITHUB_SHA) throw new Error(`Artifact commit mismatch: ${platform}`);
  for (const archive of manifest.archives) {
    if (fileSha256(join(directory, archive.filename)) !== archive.sha256) throw new Error(`Checksum mismatch: ${archive.filename}`);
  }
  for (const major of [22, 24]) {
    const runtime = JSON.parse(readFileSync(join(directory, `runtime-node${major}.json`)));
    if (!runtime.passed || runtime.platform !== platform || !runtime.node.startsWith(`v${major}.`) || runtime.nativeSha256 !== manifest.build.sha256) throw new Error(`Missing matching runtime evidence: ${platform}/Node ${major}`);
    for (const archive of manifest.archives) {
      if (!runtime.archives.some((tested) => tested.filename === archive.filename && tested.sha256 === archive.sha256)) throw new Error(`Runtime did not test current archive: ${archive.filename}`);
    }
  }
  const rootArchive = manifest.archives.find(({ filename }) => filename === `${packageManifest.name}-${packageManifest.version}.tgz`);
  if (!rootArchive) throw new Error(`Missing root archive: ${platform}`);
  outcomes.push({ platform, rootArchiveSha256: rootArchive.sha256, sourceSha256: manifest.build.source.sourceSha256, commit: manifest.build.source.commit, nativeSha256: manifest.build.sha256, archives: manifest.archives });
}
if (new Set(outcomes.map((item) => item.commit)).size !== 1) throw new Error('Platform builds have different source commits');
if (new Set(outcomes.map((item) => item.rootArchiveSha256)).size !== 1) throw new Error('Platform packages did not test the same root archive');
writeFileSync(join(root, 'dist/release-verification.json'), `${JSON.stringify({ schemaVersion: 1, passed: true, outcomes }, null, 2)}\n`);
console.log('All seven platforms have matching archives and successful Node.js 22/24 installation evidence.');
