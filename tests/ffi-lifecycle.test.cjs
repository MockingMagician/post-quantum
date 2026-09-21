'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { Worker } = require('node:worker_threads');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const pq = require('../index.cjs');
const modulePath = require.resolve('../index.cjs');

test('production native module exposes no validation hooks', () => {
  for (const name of Object.getOwnPropertyNames(pq)) assert.ok(!name.startsWith('__'), name);
});

test('the production loader rejects validation hooks and incomplete native APIs', () => {
  const source = readFileSync(modulePath, 'utf8');
  function load(native) {
    const sandbox = {
      module: { exports: {} }, __dirname: require('node:path').dirname(modulePath),
      require(name) {
        if (name === 'node:fs') return { existsSync: () => true };
        if (name === 'node:path') return require(name);
        if (name === './lib/platform.cjs') return () => 'linux-x64-gnu';
        if (name.endsWith('.node')) return native;
        throw new Error(`Unexpected dependency: ${name}`);
      },
    };
    runInNewContext(source, sandbox);
    return sandbox.module.exports;
  }
  assert.equal(load(pq), pq);
  const withHooks = Object.defineProperties({}, Object.getOwnPropertyDescriptors(pq));
  Object.defineProperty(withHooks, '__setFault', { value() {} });
  assert.throws(() => load(withHooks), { code: 'ERR_NATIVE_BINDING_UNAVAILABLE' });
  assert.throws(() => load({}), { code: 'ERR_NATIVE_BINDING_UNAVAILABLE' });
});

test('retained Promise executors cannot reuse expired native construction state', () => {
  const result = spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    const NativePromise = Promise;
    const executors = [];
    global.Promise = class ObservedPromise extends NativePromise {
      constructor(executor) {
        if (executor.name !== 'postQuantumPromise') { super(executor); return; }
        super((resolve, reject) => {
          if (executors.length) {
            assert.throws(() => executors[0](resolve, reject), { code: 'ERR_INVALID_ARGUMENT' });
          }
          executors.push(executor);
          executor(resolve, reject);
          assert.throws(() => executor(resolve, reject), { code: 'ERR_INVALID_ARGUMENT' });
        });
      }
    };
    const pq = require(process.argv[1]);
    global.Promise = NativePromise;
    (async () => {
      const pair = await pq.generateEncryptionKeyPair();
      assert.throws(() => executors[0](() => {}, () => {}), { code: 'ERR_INVALID_ARGUMENT' });
      const message = Buffer.from('Promise executor lifetime');
      assert.deepEqual(await pq.decrypt(pair.privateKey, await pq.encrypt(pair.publicKey, message)), message);
      await pair.privateKey.destroy();
      assert.ok(executors.length >= 4);
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `, modulePath], { encoding: 'utf8', timeout: 20000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
});

test('pending operations own the Rust key after JavaScript garbage collection', () => {
  const result = spawnSync(process.execPath, ['--expose-gc', '-e', `
    const assert = require('node:assert/strict');
    const pq = require(process.argv[1]);
    (async () => {
      let pair = await pq.generateSigningKeyPair();
      const publicKey = pair.publicKey;
      const message = Buffer.alloc(2 * 1024 * 1024, 7);
      const signature = pq.sign(pair.privateKey, message);
      pair = null;
      for (let i = 0; i < 4; i++) global.gc();
      assert.equal(await pq.verify(publicKey, message, await signature), true);
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `, modulePath], { encoding: 'utf8', timeout: 20000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
});

test('terminating Workers drains queued and running native work without abort or deadlock', { timeout: 30000 }, async () => {
  for (let iteration = 0; iteration < 4; iteration++) {
    const worker = new Worker(`
      const { parentPort, workerData } = require('node:worker_threads');
      const pq = require(workerData);
      (async () => {
        const pair = await pq.generateSigningKeyPair();
        const message = Buffer.alloc(2 * 1024 * 1024, 9);
        const operations = Array.from({ length: 24 }, () => pq.sign(pair.privateKey, message));
        Promise.allSettled(operations);
        parentPort.postMessage('queued');
      })().catch(error => { throw error; });
    `, { eval: true, workerData: modulePath });
    await new Promise((resolve, reject) => {
      worker.once('message', value => value === 'queued' ? resolve() : reject(new Error('Unexpected message')));
      worker.once('error', reject);
    });
    const exit = await worker.terminate();
    assert.ok(exit === 0 || exit === 1);
    // The parent environment remains usable after another env's cleanup.
    const pair = await pq.generateEncryptionKeyPair();
    try {
      const message = Buffer.from(`environment ${iteration}`);
      assert.deepEqual(await pq.decrypt(pair.privateKey, await pq.encrypt(pair.publicKey, message)), message);
    } finally { await pair.privateKey.destroy(); }
  }
});
