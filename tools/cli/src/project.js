import * as fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fail } from './errors.js';
import { projectRoot, readOptional, safePath, privateDirectory } from './files.js';
import { localChecks } from './local-checks.js';

const platforms=['android','expo','flutter'];
const profiles=['basic','balanced','strict'];
export const androidProtection=`// AppGuard release protection. Review keep rules for reflection/JNI/frameworks.\nplugins.withId('com.android.application') {\n    android {\n        buildTypes {\n            release {\n                minifyEnabled true\n                shrinkResources true\n                proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n            }\n        }\n    }\n}\n`;
const id=v=>typeof v==='string' && /^[A-Za-z0-9._:-]{1,128}$/.test(v);
const plain=v=>v!==null && typeof v==='object' && !Array.isArray(v) && Object.getPrototypeOf(v)===Object.prototype;
function keys(value,allowed) { return plain(value) && Object.keys(value).every(k=>allowed.includes(k)); }
export function validatePolicy(policy) {
  if(!keys(policy,['profile','requireSignature']) || !profiles.includes(policy.profile) || typeof policy.requireSignature!=='boolean' || (!policy.requireSignature && policy.profile!=='basic')) fail('INVALID_POLICY');
  return {valid:true,profile:policy.profile,requireSignature:policy.requireSignature};
}
async function detect(root) {
  const result=[];
  const pkg=await readOptional(root,'package.json');
  if(pkg!==null) {
    let data; try {data=JSON.parse(pkg);} catch {fail('INVALID_PROJECT');}
    if(plain(data) && (data.dependencies?.expo || data.devDependencies?.expo)) result.push('expo');
  }
  const pub=await readOptional(root,'pubspec.yaml');
  if(pub!==null && /^\s*flutter\s*:/m.test(pub)) result.push('flutter');
  // Native folders are expected inside Expo projects and do not create ambiguity.
  if(!result.includes('expo') && ((await readOptional(root,'app/build.gradle'))!==null || (await readOptional(root,'app/build.gradle.kts'))!==null)) result.push('android');
  return result;
}
function validateConfig(config) {
  if(!keys(config,['schemaVersion','appId','platform','profile','requireSignature','androidBuildFile']) || config.schemaVersion!=='appguard-project-v0' || !id(config.appId) || !platforms.includes(config.platform)) fail('INVALID_CONFIG');
  validatePolicy({profile:config.profile,requireSignature:config.requireSignature});
  if(config.platform==='android' && !['app/build.gradle','app/build.gradle.kts'].includes(config.androidBuildFile)) fail('INVALID_CONFIG');
  if(config.platform!=='android' && config.androidBuildFile!==undefined) fail('INVALID_CONFIG');
  return config;
}
export async function loadProject(input) {
  const root=await projectRoot(input);
  const text=await readOptional(root,'appguard.json',65536);
  if(text===null) fail('CONFIG_MISSING');
  let config; try {config=JSON.parse(text);} catch {fail('INVALID_CONFIG');}
  return {root,config:validateConfig(config)};
}
export async function initialize(input,options) {
  if(!keys(options,['appId','platform','profile']) || !id(options.appId) || (options.platform!==undefined && !platforms.includes(options.platform)) || (options.profile!==undefined && !profiles.includes(options.profile))) fail('INVALID_OPTIONS');
  const root=await projectRoot(input);
  const lock=await safePath(root,'.appguard-init.lock');
  try {await fs.mkdir(lock,{mode:0o700});} catch(e) {if(e.code==='EEXIST') fail('PROJECT_BUSY'); throw e;}
  const changed=[];
  try {
    if(await readOptional(root,'appguard.json')!==null) fail('CONFIG_EXISTS');
    const detected=await detect(root);
    const platform=options.platform ?? (detected.length===1 ? detected[0] : undefined);
    if(!platform) fail(detected.length>1?'PLATFORM_AMBIGUOUS':'PLATFORM_UNSUPPORTED');
    if(!detected.includes(platform)) fail('PLATFORM_MISMATCH');
    const config={schemaVersion:'appguard-project-v0',appId:options.appId,platform,profile:options.profile??'balanced',requireSignature:true};
    const updates=[];
    const ignore=await readOptional(root,'.gitignore');
    if(ignore===null || !ignore.split(/\r?\n/).some(line=>line==='.appguard/' || line==='/.appguard/')) updates.push(['.gitignore',ignore,(ignore??'')+((ignore??'').endsWith('\n') || !ignore?'':'\n')+'.appguard/\n']);
    if(platform==='android') {
      const groovy=await readOptional(root,'app/build.gradle');
      const kotlin=await readOptional(root,'app/build.gradle.kts');
      if(groovy!==null && kotlin!==null) fail('PLATFORM_AMBIGUOUS');
      config.androidBuildFile=groovy!==null?'app/build.gradle':'app/build.gradle.kts';
      if(await readOptional(root,'app/appguard-release.gradle')!==null) fail('CONFIG_EXISTS');
      const rules=await readOptional(root,'app/proguard-rules.pro');
      if(rules===null) updates.push(['app/proguard-rules.pro',null,'# Add application-specific reflection/JNI keep rules here.\n']);
      updates.push(['app/appguard-release.gradle',null,androidProtection]);
      const before=groovy??kotlin;
      const apply=groovy!==null?"apply from: 'appguard-release.gradle'":'apply(from = "appguard-release.gradle")';
      updates.push([config.androidBuildFile,before,before+(before.endsWith('\n')?'':'\n')+apply+'\n']);
    }
    updates.push(['appguard.json',null,JSON.stringify(config,null,2)+'\n']);
    // Preflight every target before any application file is changed.
    for(const [name,before] of updates) if(await readOptional(root,name)!==before) fail('PROJECT_CHANGED');
    const privateDir=await privateDirectory(root,'.appguard');
    const backup=path.join(privateDir,`init-${randomUUID()}`);
    await fs.mkdir(backup,{mode:0o700});
    for(let i=0;i<updates.length;i++) {
      const [name,before,after]=updates[i];
      if(before!==null) await fs.writeFile(path.join(backup,`${i}.original`),before,{mode:0o600,flag:'wx'});
      const file=await safePath(root,name);
      if(await readOptional(root,name)!==before) fail('PROJECT_CHANGED');
      if(before===null) await fs.writeFile(file,after,{flag:'wx',mode:0o600});
      else {
        const st=await fs.lstat(file);
        const tmp=file+`.appguard-${randomUUID()}`;
        await fs.writeFile(tmp,after,{flag:'wx',mode:st.mode&0o777});
        try {if(await readOptional(root,name)!==before) fail('PROJECT_CHANGED'); await fs.rename(tmp,file);} finally {await fs.rm(tmp,{force:true});}
      }
      changed.push({name,before,after});
    }
    await fs.writeFile(path.join(backup,'manifest.json'),JSON.stringify(changed.map(({name,before})=>({name,existed:before!==null})),null,2)+'\n',{flag:'wx',mode:0o600});
    return {config,files:changed.map(x=>x.name),backupDirectory:backup};
  } catch(e) {
    for(const {name,before,after} of changed.reverse()) {
      if(await readOptional(root,name)===after) {
        const file=await safePath(root,name);
        if(before===null) await fs.unlink(file); else await fs.writeFile(file,before);
      }
    }
    throw e;
  } finally {await fs.rmdir(lock);}
}
export async function inspect(input) {
  const {root,config}=await loadProject(input);
  let protectionConfigured=true;
  if(config.platform==='android') {
    const build=await readOptional(root,config.androidBuildFile);
    const apply=config.androidBuildFile.endsWith('.kts')?'apply(from = "appguard-release.gradle")':"apply from: 'appguard-release.gradle'";
    protectionConfigured=await readOptional(root,'app/appguard-release.gradle')===androidProtection && build!==null && build.split(/\r?\n/).includes(apply);
  }
  const checks=await localChecks(root,config,protectionConfigured);
  return {configurationValid:true,platform:config.platform,appId:config.appId,profile:config.profile,protectionConfigured,sdkInstalled:'not_checked',providerConfigured:'not_checked',buildVerified:false,checks,localChecksPassed:checks.every(check=>check.status==='pass')};
}
