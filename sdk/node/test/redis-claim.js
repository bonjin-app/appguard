// Cross-language local evidence helper. No raw input/error details in output.
import { createClient } from 'redis';
import { RedisReplayStore } from '../src/index.js';
const client = createClient({ url: process.env.APPGUARD_TEST_REDIS_URL });
client.on('error', () => {});
try {
  const [app, key, nonce, now, expires] = process.argv.slice(2);
  await client.connect();
  const claimed = await new RedisReplayStore(client).claim([app, key, nonce], { now: Number(now), expires: Number(expires) });
  process.stdout.write(`${claimed ? 'CLAIMED' : 'REPLAY'}\n`);
} catch { process.stdout.write('UNAVAILABLE\n'); process.exitCode = 1; }
finally { if (client.isOpen) await client.close(); }
