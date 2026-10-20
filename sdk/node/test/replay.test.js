import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createClient } from 'redis';
import { InMemoryReplayStore, RedisReplayStore, redisReplayKey } from '../src/index.js';
const scope = () => ['node-test', 'node-key', randomBytes(16).toString('base64url')];
const now = 1700000000;
const times = { now, expires: now + 120 };
test('local replay is atomic under 32 concurrent callers and supports expiry', async () => {
  const store = new InMemoryReplayStore(), s = scope();
  const claims = await Promise.all(Array.from({ length: 32 }, () => Promise.resolve().then(() => store.claim(s, times))));
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(store.claim(s, { now: now + 120, expires: now + 121 }), true);
});
test('local store capacity never evicts live security claims', () => {
  const store = new InMemoryReplayStore({ capacity: 1 }), first = scope();
  assert.equal(store.claim(first, times), true);
  assert.throws(() => store.claim(scope(), times), { code: 'REPLAY_STORE_UNAVAILABLE' });
  assert.equal(store.claim(first, times), false);
});
test('Redis namespace is compact JSON SHA-256 and uses one atomic SET NX EX', async () => {
  const s = ['test-app', 'test-key', 'AAECAwQFBgcICQoLDA0ODw'];
  const expected = `appguard:v0:replay:${createHash('sha256').update('["test-app","test-key","AAECAwQFBgcICQoLDA0ODw"]').digest('hex')}`;
  assert.equal(redisReplayKey(s), expected);
  let commands = [];
  const store = new RedisReplayStore({ sendCommand: async args => { commands.push(args); return 'OK'; } });
  assert.equal(await store.claim(s, times), true);
  assert.deepEqual(commands, [['SET', expected, '1', 'NX', 'EX', '120']]);
});
for (const result of [null, false, true, 0, 1, 'yes', undefined, Buffer.from('OK')]) test(`Redis response contract: ${String(result)}`, async () => {
  const store = new RedisReplayStore({ sendCommand: async () => result });
  if (result === null) assert.equal(await store.claim(scope(), times), false);
  else await assert.rejects(store.claim(scope(), times), { code: 'REPLAY_STORE_UNAVAILABLE' });
});
for (const deadline of [{now, expires: now}, {now, expires: now + 151}, {now: true, expires: now + 1}, {now, expires: now + 0.5}]) test(`Redis rejects invalid deadline: ${JSON.stringify(deadline)}`, async () => {
  let called = false;
  const store = new RedisReplayStore({ sendCommand: async () => { called = true; return 'OK'; } });
  await assert.rejects(store.claim(scope(), deadline), { code: 'REPLAY_STORE_UNAVAILABLE' }); assert.equal(called, false);
});
for (const s of [[], ['a', 'b', 'bad'], ['a', 'b', 'AAECAwQFBgcICQoLDA0ODx'], ['a b', 'b', 'AAECAwQFBgcICQoLDA0ODw']]) test('Redis rejects invalid scope before command', async () => {
  let called = false;
  const store = new RedisReplayStore({ sendCommand: async () => { called = true; return 'OK'; } });
  await assert.rejects(store.claim(s, times), { code: 'REPLAY_STORE_UNAVAILABLE' }); assert.equal(called, false);
});
test('Redis errors expose only fixed code', async () => {
  const store = new RedisReplayStore({ sendCommand: async () => { throw new Error('secret endpoint'); } });
  await assert.rejects(store.claim(scope(), times), error => error.code === 'REPLAY_STORE_UNAVAILABLE' && error.message === 'REPLAY_STORE_UNAVAILABLE');
});
test('live Redis independent clients accept one of 32 claims, retain TTL and reject disconnected backend', { skip: !process.env.APPGUARD_TEST_REDIS_URL }, async () => {
  const clients = [createClient({ url: process.env.APPGUARD_TEST_REDIS_URL }), createClient({ url: process.env.APPGUARD_TEST_REDIS_URL })];
  clients.forEach(c => c.on('error', () => {})); await Promise.all(clients.map(c => c.connect()));
  const s = scope(), key = redisReplayKey(s), stores = clients.map(c => new RedisReplayStore(c));
  try {
    const claimed = await Promise.all(Array.from({ length: 32 }, (_, i) => stores[i % 2].claim(s, times)));
    assert.equal(claimed.filter(Boolean).length, 1); assert.equal(claimed.filter(v => v === false).length, 31);
    const ttl = await clients[0].ttl(key); assert.ok(ttl > 0 && ttl <= 120);
    await clients[1].close();
    await assert.rejects(stores[1].claim(scope(), times), { code: 'REPLAY_STORE_UNAVAILABLE' });
  } finally { await clients[0].del(key); for (const c of clients) if (c.isOpen) await c.close(); }
});
