import Fastify from 'fastify';
import {createClient} from 'redis';
import {createServer} from 'node:http';
import { buildSignatureBase, verifyRequest, parseSignatures, RedisReplayStore, InMemoryReplayStore, expressMiddleware, nestMiddleware, installFastify, type AdapterOptions, type KeyRecord, type VerificationResult } from '@appguard/server';
const key: KeyRecord = { app_id:'a', key_id:'k', subject:'u', public_key_pem:'pem', algorithm:'ecdsa-p256-sha256', revoked:false };
const combined: AdapterOptions = { app_id:'a', origin:'https://api.example.test', replay:new InMemoryReplayStore(), identityResolver: async context => ({subject:'u', key}) };
const separate: AdapterOptions = { app_id:'a', origin:'https://api.example.test', replay:new RedisReplayStore({sendCommand: async args => 'OK'}), identityResolver: async () => 'u', keyResolver: async context => key };
expressMiddleware(combined); nestMiddleware(separate); installFastify({server:createServer(),addHook: () => {}}, combined);
// @ts-expect-error an identity callback is mandatory
expressMiddleware({ app_id:'a', origin:'https://api.example.test', replay:new InMemoryReplayStore() });
// @ts-expect-error a string identity requires a separate trusted key resolver
expressMiddleware({ app_id:'a', origin:'https://api.example.test', replay:new InMemoryReplayStore(), identityResolver: () => 'u' });
// @ts-expect-error a replay store is mandatory
expressMiddleware({ app_id:'a', origin:'https://api.example.test', identityResolver: () => ({subject:'u', key}) });
const parsed = parseSignatures([['Signature','value']]);
const request = {method:'POST',target:'/',headers:[['Content-Type','application/json']] as [string,string][],body:Buffer.from('{}')};
buildSignatureBase(request, parsed.parameters, {origin:'https://api.example.test'});
const result: Promise<VerificationResult> = verifyRequest(request, parsed.parameters, parsed.signature, {origin:'https://api.example.test',app_id:'a',subject:'u',key,now:0,replay:new InMemoryReplayStore()});

installFastify(Fastify(), combined);
new RedisReplayStore(createClient());
