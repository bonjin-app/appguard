const {test}=require('node:test');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {readFileSync,existsSync}=require('node:fs');
const {createHash}=require('node:crypto');
test('staging is deterministic and includes exact native facades and licenses',()=>{
 execFileSync(process.execPath,['scripts/stage-native.mjs']);
 const a=readFileSync('PROVENANCE.json','utf8');
 const manifest=JSON.parse(a);
 for(const [file,sha] of Object.entries(manifest.files)) assert.equal(createHash('sha256').update(readFileSync(file)).digest('hex'),sha);
 for(const file of ['vendor/android/src/main/java/io/appguard/android/NativeBridge.java','vendor/apple/Sources/AppGuardApple/NativeBridge.swift','vendor/android/LICENSE','vendor/apple/LICENSE']) assert.ok(existsSync(file));
 execFileSync(process.execPath,['scripts/stage-native.mjs']);
 assert.equal(readFileSync('PROVENANCE.json','utf8'),a);
});
