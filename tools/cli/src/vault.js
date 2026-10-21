import * as fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
import {fail} from './errors.js';
import {projectRoot,safePath,privateDirectory} from './files.js';

const MAX_BYTES=64*1024*1024,MAX_PAYLOAD=96*1024*1024,MAX_ARCHIVE=128*1024*1024,MAX_FILES=1000;
const VERSION='appguard-vault-v0';
const buildIdValid=v=>typeof v==='string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v);
const exact=(obj,names)=>obj!==null && typeof obj==='object' && !Array.isArray(obj) && Object.keys(obj).length===names.length && names.every(k=>Object.hasOwn(obj,k));
const safeName=n=>typeof n==='string' && n.length<=1024 && !n.includes('\\') && !n.includes(':') && !/[\x00-\x1f\x7f]/.test(n) && !path.isAbsolute(n) && n.split('/').length<=16 && n.split('/').every(p=>p.length>0 && p.length<=200 && p!=='.' && p!=='..' && !/[. ]$/.test(p) && !/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i.test(p));
// The same portability gate runs before retention, verification and restore.
export function validatePortablePaths(names) {
  if(!Array.isArray(names) || !names.length || names.length>MAX_FILES) fail('ARCHIVE_REJECTED');
  const folded=new Set();
  for(const name of names) {
    if(!safeName(name)) fail('ARCHIVE_REJECTED');
    const lower=name.normalize('NFC').toLowerCase();
    if(folded.has(lower)) fail('ARCHIVE_REJECTED');folded.add(lower);
  }
  for(const name of folded) {let parent=path.posix.dirname(name);while(parent!=='.') {if(folded.has(parent)) fail('ARCHIVE_REJECTED');parent=path.posix.dirname(parent);}}
}
function decode(value,max) {
  if(typeof value!=='string' || value.length>Math.ceil(max/3)*4) fail('ARCHIVE_REJECTED');
  const bytes=Buffer.from(value,'base64');
  if(bytes.length>max || bytes.toString('base64')!==value) {bytes.fill(0);fail('ARCHIVE_REJECTED');}
  return bytes;
}
async function readRegular(input,max,{privateFile=false}={}) {
  const file=path.resolve(input);
  const st=await fs.lstat(file);
  if(st.isSymbolicLink()) fail('UNSAFE_PATH');
  if(!st.isFile()) fail('INVALID_FILE');
  if(st.size>max) fail('ARCHIVE_TOO_LARGE');
  const handle=await fs.open(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try {
    const actual=await handle.stat();
    if(!actual.isFile() || actual.ino!==st.ino || actual.dev!==st.dev) fail('UNSAFE_PATH');
    if(privateFile && process.platform!=='win32' && ((actual.mode&0o077)!==0 || actual.uid!==process.getuid())) fail('UNSAFE_PERMISSIONS');
    if(actual.size>max) fail('ARCHIVE_TOO_LARGE');
    const data=Buffer.alloc(actual.size);
    let offset=0;
    while(offset<data.length) {const {bytesRead}=await handle.read(data,offset,data.length-offset,offset); if(!bytesRead) fail('INPUT_CHANGED'); offset+=bytesRead;}
    const end=await handle.stat();
    if(end.size!==actual.size || end.mtimeMs!==actual.mtimeMs || end.ctimeMs!==actual.ctimeMs) fail('INPUT_CHANGED');
    return data;
  } finally {await handle.close();}
}
async function readKey(file) {
  const key=await readRegular(file,32,{privateFile:true});
  if(key.length!==32) {key.fill(0);fail('INVALID_KEY_FILE');}
  return key;
}
async function requireNew(input,code) {
  try {await fs.lstat(input);fail(code);} catch(e) {if(e.code!=='ENOENT') throw e;}
}
async function sourceFiles(input) {
  if((await fs.lstat(input)).isSymbolicLink()) fail('UNSAFE_PATH');
  const root=await projectRoot(input),files=[];
  let total=0;
  async function walk(relative='') {
    const entries=await fs.readdir(relative?await safePath(root,relative):root,{withFileTypes:true});
    entries.sort((a,b)=>a.name.localeCompare(b.name));
    for(const entry of entries) {
      const name=relative?relative+'/'+entry.name:entry.name;
      if(!safeName(name)) fail('UNSAFE_PATH');
      const file=await safePath(root,name);
      if(entry.isDirectory()) await walk(name);
      else if(entry.isFile()) {
        if(files.length>=MAX_FILES) fail('ARCHIVE_TOO_LARGE');
        const size=(await fs.lstat(file)).size;
        if(size>MAX_BYTES-total) fail('ARCHIVE_TOO_LARGE');
        const body=await readRegular(file,MAX_BYTES-total);
        total+=body.length;
        files.push({path:name,bodyBase64:body.toString('base64')});
      } else fail('UNSAFE_PATH');
    }
  }
  await walk();
  if(!files.length) fail('ARCHIVE_EMPTY');
  return {root,files,total};
}
function aad(buildId) {return Buffer.from(JSON.stringify([VERSION,buildId]));}
export async function archive({source,vault,keyFile,buildId}) {
  if(!buildIdValid(buildId)) fail('INVALID_BUILD_ID');
  const key=await readKey(keyFile);
  try {
    // Check containment before creating a vault or walking its contents.
    const sourceRoot=await projectRoot(source);
    const vaultParent=await fs.realpath(path.dirname(path.resolve(vault)));
    const vaultPath=path.join(vaultParent,path.basename(path.resolve(vault)));
    if(vaultPath===sourceRoot || vaultPath.startsWith(sourceRoot+path.sep)) fail('UNSAFE_PATH');
    const {files,total}=await sourceFiles(source);
    validatePortablePaths(files.map(entry=>entry.path));
    const directory=await privateDirectory(vaultParent,path.basename(vaultPath));
    const archiveFile=await safePath(directory,buildId+'.agvault');
    await requireNew(archiveFile,'ARCHIVE_EXISTS');
    const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
    cipher.setAAD(aad(buildId));
    const plaintext=Buffer.from(JSON.stringify({files}));
    let encrypted;
    try {encrypted=Buffer.concat([cipher.update(plaintext),cipher.final()]);} finally {plaintext.fill(0);}
    const envelope={schemaVersion:VERSION,buildId,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')};
    const serialized=JSON.stringify(envelope)+'\n';
    if(Buffer.byteLength(serialized)>MAX_ARCHIVE) fail('ARCHIVE_TOO_LARGE');
    let handle;
    try {handle=await fs.open(archiveFile,'wx',0o600);} catch(e) {if(e.code==='EEXIST') fail('ARCHIVE_EXISTS');throw e;}
    try {await handle.writeFile(serialized);await handle.sync();} catch(e) {await fs.unlink(archiveFile);throw e;} finally {await handle.close();}
    return {archiveFile,buildId,fileCount:files.length,plaintextBytes:total,sourceRetained:true};
  } finally {key.fill(0);}
}
async function withValidatedArchive({archiveFile,keyFile},consume) {
  const key=await readKey(keyFile);
  const files=[];
  let plaintext,chunk,tail;
  try {
    const bytes=await readRegular(archiveFile,MAX_ARCHIVE);
    let envelope;
    try {envelope=JSON.parse(bytes.toString('utf8'));} catch {fail('ARCHIVE_REJECTED');}
    if(!exact(envelope,['schemaVersion','buildId','iv','tag','ciphertext']) || envelope.schemaVersion!==VERSION || !buildIdValid(envelope.buildId)) fail('ARCHIVE_REJECTED');
    const iv=decode(envelope.iv,12),tag=decode(envelope.tag,16),ciphertext=decode(envelope.ciphertext,MAX_PAYLOAD);
    if(iv.length!==12 || tag.length!==16) fail('ARCHIVE_REJECTED');
    try {
      const decipher=createDecipheriv('aes-256-gcm',key,iv);decipher.setAAD(aad(envelope.buildId));decipher.setAuthTag(tag);
      chunk=decipher.update(ciphertext);tail=decipher.final();
      plaintext=Buffer.concat([chunk,tail]);
    } catch {fail('ARCHIVE_REJECTED');}
    finally {chunk?.fill(0);tail?.fill(0);}
    let payload;
    try {payload=JSON.parse(plaintext.toString('utf8'));} catch {fail('ARCHIVE_REJECTED');} finally {plaintext.fill(0);}
    if(!exact(payload,['files']) || !Array.isArray(payload.files) || !payload.files.length || payload.files.length>MAX_FILES) fail('ARCHIVE_REJECTED');
    const names=new Set();let total=0;
    for(const entry of payload.files) {
      if(!exact(entry,['path','bodyBase64']) || !safeName(entry.path) || names.has(entry.path)) fail('ARCHIVE_REJECTED');
      const data=decode(entry.bodyBase64,MAX_BYTES-total);total+=data.length;
      names.add(entry.path);files.push({name:entry.path,data});
    }
    validatePortablePaths(files.map(entry=>entry.name));
    return await consume({buildId:envelope.buildId,files,total});
  } finally {key.fill(0);plaintext?.fill(0);for(const {data} of files) data.fill(0);}
}
export async function verifyArchive({archiveFile,keyFile}) {
  return withValidatedArchive({archiveFile,keyFile},({buildId,files,total})=>
    ({verified:true,buildId,fileCount:files.length,plaintextBytes:total}));
}
export async function restore({archiveFile,destination,keyFile}) {
  return withValidatedArchive({archiveFile,keyFile},async({buildId,files,total})=>{
    const target=path.resolve(destination);
    const parent=await fs.realpath(path.dirname(target));
    const actual=path.join(parent,path.basename(target));
    await requireNew(actual,'DESTINATION_EXISTS');
    await fs.mkdir(actual,{mode:0o700});
    try {
      for(const {name,data} of files) {
        const file=await safePath(actual,name);
        await fs.mkdir(path.dirname(file),{recursive:true,mode:0o700});
        await fs.writeFile(file,data,{flag:'wx',mode:0o600});
      }
    } catch(e) {await fs.rm(actual,{recursive:true,force:true});throw e;}
    return {buildId,destination:actual,fileCount:files.length,plaintextBytes:total};
  });
}
