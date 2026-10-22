import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { loadProject, inspect } from './project.js';
import { privateDirectory, safePath } from './files.js';
import { fail } from './errors.js';
import {expoEntrypoint} from './expo-tool.js';

export async function buildPlan(input) {
  const {root,config}=await loadProject(input);
  if(!(await inspect(root)).protectionConfigured) fail('PROTECTION_NOT_CONFIGURED');
  const base={platform:config.platform,cwd:root,executed:false};
  if(config.platform==='android') return {...base,command:path.join(root,process.platform==='win32'?'gradlew.bat':'gradlew'),args:[':app:assembleRelease'],protection:'r8-release',mappingDirectory:path.join(root,'app/build/outputs/mapping/release')};
  if(config.platform==='flutter') return {...base,command:'flutter',args:['build','apk','--release','--obfuscate',`--split-debug-info=${path.join(root,'.appguard','symbols')}`],protection:'dart-aot-obfuscation',mappingDirectory:path.join(root,'.appguard','symbols')};
  return {...base,command:process.execPath,args:[path.join(root,'node_modules/expo/bin/cli'),'export','--platform','all','--output-dir',path.join(root,'dist')],protection:'production-minification',mappingDirectory:null};
}
export async function executeBuild(input) {
  const plan=await buildPlan(input);
  await privateDirectory(plan.cwd,'.appguard');
  if(plan.platform==='flutter') await privateDirectory(plan.cwd,'.appguard/symbols');
  else {
    const executable=plan.platform==='android'?(process.platform==='win32'?'gradlew.bat':'gradlew'):'node_modules/expo/bin/cli';
    try {
      const file=plan.platform==='expo'?await expoEntrypoint(plan.cwd):await safePath(plan.cwd,executable);
      if(!(await fs.lstat(file)).isFile()) fail('BUILD_TOOL_MISSING');
      if(plan.platform==='expo') plan.args[0]=file;
    } catch(e) {if(e.code==='ENOENT' || e.code==='ENOTDIR') fail('BUILD_TOOL_MISSING');throw e;}
  }
  if(process.platform==='win32' && plan.platform==='android') fail('PLATFORM_UNSUPPORTED');
  const exitCode=await new Promise((resolve,reject)=>{
    const child=spawn(plan.command,plan.args,{cwd:plan.cwd,shell:false,stdio:['ignore','inherit','inherit']});
    child.once('error',()=>{try {fail('BUILD_TOOL_UNAVAILABLE');} catch(e) {reject(e);}});
    child.once('exit',(code,signal)=>resolve(signal?1:code??1));
  });
  return {...plan,executed:true,exitCode};
}
