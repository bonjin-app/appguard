import { readFile, readdir, mkdir, rm, copyFile, lstat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repository = path.resolve(root, '../..');
const vendor = path.join(root, 'vendor');
// Repository-only packaging step. Never runs on consumer installation.
const entries = [
  ['sdk/android/LICENSE','android/LICENSE'],
  ['sdk/android/src/main/java','android/src/main/java'],
  ['sdk/apple/LICENSE','apple/LICENSE'],
  ['sdk/apple/Sources/AppGuardApple','apple/Sources/AppGuardApple'],
];
for (const facade of ['sdk/android/src/main/java/io/appguard/android/NativeBridge.java','sdk/apple/Sources/AppGuardApple/NativeBridge.swift']) await readFile(path.join(repository,facade));
const files = [];
async function collect(source, target) {
  const info = await lstat(path.join(repository, source));
  if (info.isSymbolicLink()) throw new Error('APPGUARD_STAGING_SYMLINK');
  if (info.isDirectory()) {
    for (const child of (await readdir(path.join(repository,source))).sort()) await collect(`${source}/${child}`,`${target}/${child}`);
  } else if (info.isFile()) files.push({source,target});
  else throw new Error('APPGUARD_STAGING_FILE_TYPE');
}
for (const [source,target] of entries) await collect(source,target);
await rm(vendor,{recursive:true,force:true});
const hashes = {};
for (const {source,target} of files) {
  const output = path.join(vendor,target);
  await mkdir(path.dirname(output),{recursive:true});
  await copyFile(path.join(repository,source),output);
  hashes[`vendor/${target}`] = createHash('sha256').update(await readFile(output)).digest('hex');
}
const manifest = {
  schema:1, note:'Native SDK source snapshot. SHA-256 values identify exact content, including uncommitted changes.',
  repositoryCommit:execFileSync('git',['rev-parse','HEAD'],{cwd:repository,encoding:'utf8'}).trim(),
  sourcePaths:entries.map(([source])=>source), files:hashes,
};
await writeFile(path.join(root,'PROVENANCE.json'),JSON.stringify(manifest,null,2)+'\n');
console.error(`Staged ${files.length} native source/license files inside the package`);
