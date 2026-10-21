import * as fs from 'node:fs/promises';
import { isUtf8 } from 'node:buffer';
import path from 'node:path';
import { fail } from './errors.js';

export async function projectRoot(input) {
  const root=await fs.realpath(input);
  if(!(await fs.stat(root)).isDirectory()) fail('INVALID_PROJECT');
  return root;
}
export async function safePath(root, relative) {
  if(typeof relative!=='string' || !relative || path.isAbsolute(relative) || relative.split(/[\\/]/).some(p=>p==='..'||p==='.')) fail('UNSAFE_PATH');
  const parts=relative.split('/');
  let current=root;
  for(let i=0;i<parts.length;i++) {
    current=path.join(current,parts[i]);
    try {
      const st=await fs.lstat(current);
      if(st.isSymbolicLink() || (i<parts.length-1 && !st.isDirectory())) fail('UNSAFE_PATH');
    } catch(e) { if(e.code!=='ENOENT') throw e; }
  }
  return current;
}
export async function readOptional(root,relative,max=1048576) {
  const file=await safePath(root,relative);
  try {
    const st=await fs.lstat(file);
    if(!st.isFile() || st.size>max) fail('INVALID_FILE');
    const bytes=await fs.readFile(file);
    // Lossy decoding would silently rewrite input and its supposed backup.
    if(bytes.length>max || !isUtf8(bytes)) fail('INVALID_FILE');
    return bytes.toString('utf8');
  } catch(e) { if(e.code==='ENOENT') return null; throw e; }
}
export async function privateDirectory(root,relative) {
  const dest=await safePath(root,relative);
  await fs.mkdir(dest,{mode:0o700,recursive:true});
  const st=await fs.lstat(dest);
  if(!st.isDirectory() || (process.platform!=='win32' && ((st.mode&0o077)!==0 || st.uid!==process.getuid()))) fail('UNSAFE_PERMISSIONS');
  return dest;
}
