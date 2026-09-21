import pq = require('post-quantum');
const message = new Uint8Array([1, 2]);
async function useCommonJs(): Promise<boolean> {
  const keys: pq.SigningKeyPair = await pq.generateSigningKeyPair();
  try { return await pq.verify(keys.publicKey, message, await pq.sign(keys.privateKey, message)); }
  finally { await keys.privateKey.destroy(); }
}
void useCommonJs;
