#!/usr/bin/env node
import * as fs from 'node:fs/promises';
import {constants} from 'node:fs';
import {initialize,inspect,validatePolicy} from '../src/project.js';
import {buildPlan,executeBuild} from '../src/build.js';
import {archive,restore,verifyArchive} from '../src/vault.js';
import {AppGuardError,fail} from '../src/errors.js';

function options(args,allowed,flags=[]) {
  const result={};
  for(let i=0;i<args.length;i++) {
    const name=args[i];
    if(!allowed.includes(name) || Object.hasOwn(result,name)) fail('INVALID_ARGUMENTS');
    if(flags.includes(name)) result[name]=true;
    else {const value=args[++i];if(typeof value!=='string'||value.startsWith('--')||!value) fail('INVALID_ARGUMENTS');result[name]=value;}
  }
  return result;
}
function required(opts,name) {if(!opts[name]) fail('INVALID_ARGUMENTS');return opts[name];}
async function run(args) {
  const command=args.shift();
  if(command==='--help' || command==='help') return {commands:['init --app-id ID [--platform android|flutter|expo] [--profile basic|balanced|strict] [--project PATH]','doctor [--project PATH] [--check]','policy validate --file PATH','build [--project PATH] [--dry-run]','archive --source DIR --vault DIR --key-file FILE --build-id ID','restore --archive FILE --destination NEW_DIR --key-file FILE','verify-archive --archive FILE --key-file FILE'],experimental:true};
  if(command==='init') {const o=options(args,['--project','--app-id','--platform','--profile']);return initialize(o['--project']??process.cwd(),{appId:required(o,'--app-id'),...(o['--platform']?{platform:o['--platform']}:{}),...(o['--profile']?{profile:o['--profile']}:{})});}
  if(command==='doctor') {const o=options(args,['--project','--check'],['--check']);const report=await inspect(o['--project']??process.cwd());if(o['--check'] && !report.localChecksPassed) process.exitCode=2;return report;}
  if(command==='build') {const o=options(args,['--project','--dry-run'],['--dry-run']);return o['--dry-run']?buildPlan(o['--project']??process.cwd()):executeBuild(o['--project']??process.cwd());}
  if(command==='policy' && args.shift()==='validate') {
    const o=options(args,['--file']);
    const handle=await fs.open(required(o,'--file'),constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    try {const st=await handle.stat();if(!st.isFile() || st.size>65536) fail('INVALID_POLICY');return validatePolicy(JSON.parse(await handle.readFile('utf8')));} finally {await handle.close();}
  }
  if(command==='archive') {const o=options(args,['--source','--vault','--key-file','--build-id']);return archive({source:required(o,'--source'),vault:required(o,'--vault'),keyFile:required(o,'--key-file'),buildId:required(o,'--build-id')});}
  if(command==='restore') {const o=options(args,['--archive','--destination','--key-file']);return restore({archiveFile:required(o,'--archive'),destination:required(o,'--destination'),keyFile:required(o,'--key-file')});}
  if(command==='verify-archive') {const o=options(args,['--archive','--key-file']);return verifyArchive({archiveFile:required(o,'--archive'),keyFile:required(o,'--key-file')});}
  fail('INVALID_ARGUMENTS');
}
try {
  const result=await run(process.argv.slice(2));
  process.stdout.write(JSON.stringify(result)+'\n');
  if(result.exitCode) process.exitCode=result.exitCode;
} catch(e) {
  const code=e instanceof AppGuardError?e.code:'OPERATION_FAILED';
  process.stderr.write(JSON.stringify({error:{code}})+'\n');
  process.exitCode=1;
}
