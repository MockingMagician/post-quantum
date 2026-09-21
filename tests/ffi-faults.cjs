'use strict';
// Run against an isolated --features validation-hooks build, never the package binary.
const assert = require('node:assert/strict');
const { resolve } = require('node:path');
const { Worker } = require('node:worker_threads');
const pq = require(resolve(process.argv[2]));

(async () => {
  assert.equal(typeof pq.__setFault, 'function');
  assert.equal(pq.__pendingJobs(), 0);
  assert.equal(pq.__resources().jobs, 0);
  pq.__setFault(1);
  assert.throws(() => pq.generateSigningKeyPair(), { code: 'ERR_INTERNAL' });
  assert.equal(pq.__pendingJobs(), 0);
  for (const fault of [2, 3, 4, 5]) {
    pq.__setFault(fault);
    await assert.rejects(pq.generateSigningKeyPair(), { code: 'ERR_INTERNAL' });
    assert.equal(pq.__pendingJobs(), 0, `Fault ${fault} left a queued task`);
    assert.equal(pq.__resources().jobs, 0, `Fault ${fault} leaked a task allocation`);
    const pair = await pq.generateSigningKeyPair();
    const message = Buffer.from(`after failure ${fault}`);
    assert.equal(await pq.verify(pair.publicKey, message, await pq.sign(pair.privateKey, message)), true);
    await pair.privateKey.destroy();
  }
  // A failed destroy scheduling operation still revokes synchronously; retry
  // then completes erasure and remains idempotent.
  const pair = await pq.generateSigningKeyPair();
  pq.__setFault(3);
  const destruction = pair.privateKey.destroy();
  assert.equal(pair.privateKey.destroyed, true);
  await assert.rejects(destruction, { code: 'ERR_INTERNAL' });
  await assert.rejects(pair.privateKey.export(), { code: 'ERR_KEY_DESTROYED' });
  await pair.privateKey.destroy();
  assert.equal(pq.__pendingJobs(), 0);
  for (let iteration = 0; iteration < 3; iteration++) {
    global.gc(); await new Promise(resolve => setImmediate(resolve));
    const baseline = pq.__resources();
    const worker = new Worker(`
      const {parentPort, workerData} = require('node:worker_threads');
      const pq = require(workerData);
      (async () => {
        const pair = await pq.generateSigningKeyPair();
        const message = Buffer.alloc(1024 * 1024);
        Promise.allSettled(Array.from({length: 24}, () => pq.sign(pair.privateKey, message)));
        parentPort.postMessage('queued');
      })().catch(error => { throw error; });
    `, {eval:true, workerData:resolve(process.argv[2])});
    await new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); });
    await worker.terminate();
    assert.equal(pq.__resources().environments, baseline.environments, 'Worker environment leaked');
    assert.equal(pq.__resources().jobs, 0, 'Terminated Worker leaked task allocations');
    assert.ok(pq.__resources().keys <= baseline.keys, 'Terminated Worker leaked key wrappers');
  }
  console.log('PASS: isolated FFI faults, recovery, revocation and Worker resource counters');
})().catch(error => { console.error(error); process.exitCode = 1; });
