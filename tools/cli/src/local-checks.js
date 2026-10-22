import * as fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {safePath} from './files.js';
import {expoEntrypoint} from './expo-tool.js';

const result=(id,status,code)=>({id,status,code});
function failureCode(error) {
  if(error.code==='ENOENT' || error.code==='ENOTDIR') return 'MISSING';
  if(error.code==='UNSAFE_PATH' || error.code==='ELOOP') return 'UNSAFE_PATH';
  return 'UNREADABLE';
}
async function regularFile(file,accessMode,followLinks=false) {
  try {
    const stat=await (followLinks?fs.stat(file):fs.lstat(file));
    if(!stat.isFile()) return 'NOT_REGULAR_FILE';
    if(accessMode!==undefined) {
      try {await fs.access(file,accessMode);} catch(error) {
        if(error.code==='EACCES' || error.code==='EPERM') return accessMode===constants.X_OK?'NOT_EXECUTABLE':'UNREADABLE';
        throw error;
      }
    }
    return 'READY';
  } catch(error) {return failureCode(error);}
}
async function localFile(root,id,relative,accessMode) {
  let code;
  try {code=await regularFile(await safePath(root,relative),accessMode);}
  catch(error) {code=failureCode(error);}
  return result(id,code==='READY'?'pass':'fail',code);
}
async function flutterCheck(root) {
  const id='flutter_cli';
  // Windows command dispatch/PATHEXT cannot establish readiness using the
  // POSIX executable-file checks used here. Do not execute a probe to guess.
  if(process.platform==='win32') return result(id,'not_checked','PLATFORM_UNSUPPORTED');
  if(process.env.PATH===undefined) return result(id,'not_checked','PATH_NOT_SET');
  let failure='MISSING';
  for(const entry of process.env.PATH.split(path.delimiter)) {
    // spawn runs Flutter in the project directory. Empty and relative PATH
    // entries therefore refer to that directory, not the doctor's own cwd.
    const code=await regularFile(path.resolve(root,entry,'flutter'),constants.X_OK,true);
    if(code==='READY') return result(id,'pass','READY');
    if(failure==='MISSING' && code!=='MISSING') failure=code;
  }
  return result(id,'fail',failure);
}
export async function localChecks(root,config,protectionConfigured) {
  if(config.platform==='flutter') return [await flutterCheck(root)];
  if(config.platform==='expo') {
    let code;
    try {code=await regularFile(await expoEntrypoint(root),constants.R_OK);}
    catch(error) {code=failureCode(error);}
    return [result('expo_cli',code==='READY'?'pass':'fail',code)];
  }
  return [
    result('android_protection',protectionConfigured?'pass':'fail',protectionConfigured?'READY':'PROTECTION_NOT_CONFIGURED'),
    process.platform==='win32'
      ?result('android_gradle_wrapper','not_checked','PLATFORM_UNSUPPORTED')
      :await localFile(root,'android_gradle_wrapper','gradlew',constants.X_OK),
  ];
}
