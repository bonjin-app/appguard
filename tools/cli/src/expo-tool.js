import * as fs from 'node:fs/promises';
import path from 'node:path';
import {safePath} from './files.js';
import {fail} from './errors.js';

/** Resolve a local Expo package link without permitting execution outside dependencies. */
export async function expoEntrypoint(root) {
  const dependencies=await safePath(root,'node_modules');
  if(!(await fs.lstat(dependencies)).isDirectory()) fail('UNSAFE_PATH');
  const canonicalDependencies=await fs.realpath(dependencies);
  const entry=path.join(canonicalDependencies,'expo'),stat=await fs.lstat(entry);
  if(!stat.isDirectory() && !stat.isSymbolicLink()) fail('UNSAFE_PATH');
  let packageRoot;
  try {packageRoot=await fs.realpath(entry);}
  catch(error) {if(error.code==='ELOOP') fail('UNSAFE_PATH');throw error;}
  const relative=path.relative(canonicalDependencies,packageRoot);
  if(!relative || path.isAbsolute(relative) || relative.split(path.sep)[0]==='..'
      || !(await fs.lstat(packageRoot)).isDirectory()) fail('UNSAFE_PATH');
  // Keep bin and the CLI itself under the existing no-symlink policy.
  return safePath(packageRoot,'bin/cli');
}
