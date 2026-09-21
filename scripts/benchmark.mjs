import { cpus, platform, arch, release } from 'node:os';
import { performance } from 'node:perf_hooks';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as pq from '../index.mjs';
import { root, sourceIdentity, fileSha256 } from './common.mjs';
import nativePlatform from '../lib/platform.cjs';

const source = sourceIdentity();
const binary = join(root, 'native', `post_quantum.${nativePlatform()}.node`);
const build = JSON.parse(readFileSync(`${binary}.build.json`));
if (build.sha256 !== fileSha256(binary) || build.source.sourceSha256 !== source.sourceSha256) throw new Error('Rebuild the native module before benchmarking changed sources');

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--iterations')) throw new Error('Usage: node scripts/benchmark.mjs [--iterations N]');
const iterations = Number(args[1] ?? 30);
if (!Number.isInteger(iterations) || iterations < 3 || iterations > 10000) throw new Error('Iterations must be between 3 and 10000');
const rows = [];
async function measure(operation, size, fn) {
  for (let i = 0; i < 3; i++) await fn();
  const durations = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now(); await fn(); durations.push(performance.now() - start);
  }
  durations.sort((a, b) => a - b);
  rows.push({ operation, bytes: size, iterations, medianMs: durations[Math.floor(iterations / 2)], p95Ms: durations[Math.ceil(iterations * .95) - 1], meanMs: durations.reduce((a, b) => a + b, 0) / iterations });
}
const recipient = await pq.generateEncryptionKeyPair();
const author = await pq.generateSigningKeyPair();
try {
  await measure('generateEncryptionKeyPair+destroy', 0, async () => (await pq.generateEncryptionKeyPair()).privateKey.destroy());
  await measure('generateSigningKeyPair+destroy', 0, async () => (await pq.generateSigningKeyPair()).privateKey.destroy());
  for (const size of [0, 1024, 65536, 1048576, pq.MAX_MESSAGE_LEN]) {
    const message = Buffer.alloc(size, 0x5a);
    const encrypted = await pq.encrypt(recipient.publicKey, message);
    const signature = await pq.sign(author.privateKey, message);
    await measure('encrypt', size, () => pq.encrypt(recipient.publicKey, message));
    await measure('decrypt', size, () => pq.decrypt(recipient.privateKey, encrypted));
    await measure('sign', size, () => pq.sign(author.privateKey, message));
    await measure('verify', size, () => pq.verify(author.publicKey, message, signature));
  }
} finally { await Promise.all([recipient.privateKey.destroy(), author.privateKey.destroy()]); }
const report = {
  schemaVersion: 1, kind: 'performance-observation', createdAt: new Date().toISOString(),
  source, build, environment: { node: process.version, platform: platform(), arch: arch(), kernel: release(), cpu: cpus()[0]?.model, concurrency: 1 },
  note: 'Includes Node copying, worker scheduling and native operation; not a side-channel test or a throughput guarantee.', rows,
};
mkdirSync(join(root, '.reports'), { recursive: true });
if (sourceIdentity().sourceSha256 !== source.sourceSha256) throw new Error('Sources changed during benchmark; results discarded');
writeFileSync(join(root, '.reports/benchmark.json'), `${JSON.stringify(report, null, 2)}\n`);
console.table(rows);
