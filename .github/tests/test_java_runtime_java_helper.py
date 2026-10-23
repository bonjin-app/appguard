"""Actual Java17 helper on owned files, never an image/native-CI claim."""
import hashlib
import json
import os
import signal
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class JavaHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.classes=Path(cls.temporary.name)
        cls.exec_env={key:value for key,value in os.environ.items() if key not in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')}
        candidates=[Path(os.environ[key]) for key in ('APPGUARD_JAVA_HOME','JAVA_HOME_17_X64','JAVA_HOME_17_ARM64','JAVA_HOME') if key in os.environ]
        javac=shutil.which('javac')
        if javac:candidates.append(Path(javac).resolve().parent.parent)
        cls.jdk=next((path for path in candidates if (path/'bin/javac').is_file() and
            subprocess.run([str(path/'bin/javac'),'-version'],capture_output=True,timeout=5,env=cls.exec_env).stdout.startswith(b'javac 17.')),None)
        if cls.jdk is None:raise AssertionError('Java17 compiler required for actual helper tests')
        source=ROOT/'scripts/qualification/java'
        result=subprocess.run([str(cls.jdk/'bin/javac'),'--release','17','-d',str(cls.classes),
            str(source/'AppGuardRuntimeProbe.java'),str(source/'AppGuardRuntimeInventory.java')],capture_output=True,timeout=30,env=cls.exec_env)
        if result.returncode:raise AssertionError(result.stderr.decode())
        harness=cls.classes/'OwnedInventoryHarness.java'
        harness.write_text('''import java.nio.file.*;import java.util.*;
public class OwnedInventoryHarness { public static void main(String[] args)throws Exception {
if(args[0].equals("tree"))System.out.print(AppGuardRuntimeInventory.tree(Path.of(args[1]),"rhel","10.1",10001));
else if(args[0].equals("hash"))System.out.print(AppGuardRuntimeInventory.hash(Path.of(args[1]),Long.parseLong(args[2])).sha256());
else if(args[0].equals("result")){Map<String,Boolean> checks=new LinkedHashMap<>();Map<String,Boolean> entered=new LinkedHashMap<>();
for(String key:AppGuardRuntimeProbe.names()){checks.put(key,true);entered.put(key,true);}
var result=new AppGuardRuntimeProbe.ProbeResult(checks,entered,2);
System.out.println(AppGuardRuntimeProbe.legacyJson(result));System.out.println(AppGuardRuntimeInventory.featureJson(result));}
else if(args[0].equals("env")){var builder=AppGuardRuntimeInventory.builder(List.of("/usr/bin/true"));
System.out.print(builder.environment().get("HOME")+"\\n"+builder.environment().get("CODEX_HOME"));}
else if(args[0].equals("query")){try{var result=AppGuardRuntimeInventory.command(List.of(args[1],args[2]),32,1);
System.out.print(result.code()+":"+result.text());}catch(Exception error){System.exit(2);}}
}}''')
        result=subprocess.run([str(cls.jdk/'bin/javac'),'--release','17','-cp',str(cls.classes),'-d',str(cls.classes),str(harness)],capture_output=True,timeout=30,env=cls.exec_env)
        if result.returncode:raise AssertionError(result.stderr.decode())

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def run_java(self,name,*args,env=None):
        return subprocess.run([str(self.jdk/'bin/java'),'-Xmx64m','-XX:ActiveProcessorCount=1','-cp',str(self.classes),name,*args],
            capture_output=True,timeout=120,env=self.exec_env if env is None else env)

    def test_streaming_hash_matches_independent_digest_and_honors_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'owned';raw=b'owned\x00'*20000;file.write_bytes(raw)
            result=self.run_java('OwnedInventoryHarness','hash',str(file),str(len(raw)))
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(result.stdout.decode(),hashlib.sha256(raw).hexdigest())
            self.assertNotEqual(self.run_java('OwnedInventoryHarness','hash',str(file),str(len(raw)-1)).returncode,0)
            self.assertEqual(file.read_bytes(),raw)

    def test_nio_tree_observes_all_files_and_literal_links_without_os_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'legal').mkdir();(root/'legal/LICENSE').write_bytes(b'notice')
            (root/'alias').symlink_to('legal/LICENSE');(root/'release').write_text('JAVA_VERSION="17.0.20.1"\n')
            result=self.run_java('OwnedInventoryHarness','tree',str(root))
            self.assertEqual(result.returncode,0,result.stderr.decode());text=result.stdout.decode()
            self.assertIn('SYMLINK\talias\tlegal/LICENSE\n',text)
            self.assertIn('FILE\tlegal/LICENSE\t'+hashlib.sha256(b'notice').hexdigest()+'\t6\t',text)
            self.assertTrue(text.endswith('END\t2\t1\t0\n'))
            (root/'fifo').unlink(missing_ok=True);os.mkfifo(root/'fifo')
            self.assertNotEqual(self.run_java('OwnedInventoryHarness','tree',str(root)).returncode,0)

    def test_default_invalid_argument_output_is_exact_and_new_result_two_stays_unverified(self):
        invalid=self.run_java('AppGuardRuntimeProbe','invalid')
        value=json.loads(invalid.stdout);self.assertEqual(invalid.returncode,2)
        self.assertEqual(set(value),{'schema','checks','passed'});self.assertEqual(value['schema'],1)
        self.assertEqual(len(value['checks']),10);self.assertFalse(any(value['checks'].values()))
        result=self.run_java('OwnedInventoryHarness','result');legacy,modern=map(json.loads,result.stdout.splitlines())
        self.assertTrue(legacy['passed']);self.assertEqual(legacy['schema'],1)
        self.assertEqual(modern['result_code'],2);self.assertTrue(modern['checks_passed']);self.assertFalse(modern['passed'])

    def test_helper_has_no_path_option_and_child_environment_does_not_override_homes(self):
        result=self.run_java('AppGuardRuntimeInventory','tree','/owned/arbitrary')
        self.assertNotEqual(result.returncode,0);self.assertNotIn(b'/owned/arbitrary',result.stdout+result.stderr)
        env={key:value for key,value in os.environ.items() if key not in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')}
        env.update(HOME='/owned/home',CODEX_HOME='/owned/codex')
        result=self.run_java('OwnedInventoryHarness','env',env=env)
        self.assertEqual(result.stdout,b'/owned/home\n/owned/codex')

    def test_owned_query_output_and_timeout_are_bounded_and_child_settles(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);script=root/'owned-query';pid=root/'pid'
            script.write_text('#!'+sys.executable+'\nimport os,sys,time\n'
                'if sys.argv[1]=="large": print("x"*1000)\n'
                'else:\n open(sys.argv[1],"w").write(str(os.getpid()))\n time.sleep(30)\n')
            script.chmod(0o700)
            self.assertEqual(self.run_java('OwnedInventoryHarness','query',str(script),'large').returncode,2)
            result=self.run_java('OwnedInventoryHarness','query',str(script),str(pid))
            self.assertEqual(result.returncode,2)
            identifier=int(pid.read_text())
            try:
                with self.assertRaises(ProcessLookupError):os.kill(identifier,0)
            finally:
                try:os.kill(identifier,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_actual_feature_engine_has_ten_typed_observations_and_keeps_default_schema(self):
        modern=self.run_java('AppGuardRuntimeInventory','features')
        self.assertEqual(modern.returncode,0,modern.stderr.decode())
        envelope=json.loads(modern.stdout);self.assertTrue(envelope['complete'])
        value=envelope['data'];self.assertEqual(value['schema'],2);self.assertEqual(len(value['checks']),10)
        self.assertTrue(all(row['attempted'] for row in value['checks'].values()))
        self.assertTrue(all(type(row['passed']) is bool for row in value['checks'].values()))
        legacy=self.run_java('AppGuardRuntimeProbe');old=json.loads(legacy.stdout)
        self.assertEqual(set(old),{'schema','checks','passed'});self.assertEqual(old['schema'],1)
        self.assertEqual(set(old['checks']),set(value['checks']))
        self.assertTrue(all(type(flag) is bool for flag in old['checks'].values()))
        self.assertIn(legacy.returncode,(0,1,2))


if __name__=='__main__':unittest.main()
