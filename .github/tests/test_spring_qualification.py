"""Guard the local qualifier's ownership, wire format and evidence boundaries."""
import importlib.util
from contextlib import ExitStack
import json
import math
import sys
import time
import threading
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('spring_qualification',ROOT/'scripts/qualification/spring_ingress.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class QualificationTests(unittest.TestCase):
    def test_core_diagnostics_keep_only_four_safe_outcomes_and_fixed_stages(self):
        def fixture(*args):
            for _ in range(2):module.exchange(1,None,b'PRIVATE-REQUEST')
            module.core_stage('replay_rejected')
            for _ in range(3):module.exchange(1,None,b'PRIVATE-REQUEST')
            with self.assertRaises(TimeoutError):module.exchange(1,None,b'PRIVATE-REQUEST')
            return args[-1].report()
        outcomes=[(200,b'PRIVATE-BODY'),(200,b'PRIVATE-BODY'),
            (504,b'{"code":"BACKEND_TIMEOUT"}'),
            (403,b'{"code":"PRIVATE-CODE","secret":"PRIVATE-BODY"}'),
            (True,b'PRIVATE-BODY'),TimeoutError('PRIVATE-ERROR')]
        with patch.object(module,'_qualify',side_effect=fixture),patch.object(module,'_exchange',side_effect=outcomes):
            result=module.qualify(None,None,None,None)
        self.assertEqual(result['exchanges_observed'],6)
        self.assertEqual([value['ordinal'] for value in result['last_exchanges']],[3,4,5,6])
        self.assertEqual([value['status'] for value in result['last_exchanges']],[504,403,None,None])
        self.assertEqual([value['error_code'] for value in result['last_exchanges']],['BACKEND_TIMEOUT',None,None,None])
        self.assertEqual([value['exception_category'] for value in result['last_exchanges']],[None,None,None,'timeout'])
        self.assertTrue(all(value['stage']=='replay_rejected' for value in result['last_exchanges']))
        self.assertTrue(all(math.isfinite(value['elapsed_ms']) and value['elapsed_ms']>=0 for value in result['last_exchanges']))
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_core_observer_resets_after_failure_and_does_not_leak_between_runs(self):
        outer=module.CoreExchangeDiagnostics()
        token=module._core_exchange_observer.set(outer)
        def failing_fixture(*args):
            module.exchange(1,None,b'PRIVATE-REQUEST')
        def healthy_fixture(*args):
            module.exchange(1,None,b'PRIVATE-REQUEST')
            return args[-1].report()
        try:
            with patch.object(module,'_qualify',side_effect=failing_fixture),patch.object(module,'_exchange',side_effect=KeyboardInterrupt('PRIVATE-ERROR')):
                with self.assertRaises(KeyboardInterrupt):module.qualify(None,None,None,None)
            self.assertIs(module._core_exchange_observer.get(),outer)
            with patch.object(module,'_qualify',side_effect=healthy_fixture),patch.object(module,'_exchange',return_value=(200,b'PRIVATE-BODY')):
                result=module.qualify(None,None,None,None)
            self.assertEqual(result['exchanges_observed'],1)
            self.assertEqual(result['last_exchanges'][0]['ordinal'],1)
            self.assertEqual(outer.report()['exchanges_observed'],0)
            self.assertIs(module._core_exchange_observer.get(),outer)
        finally:module._core_exchange_observer.reset(token)
        self.assertIsNone(module._core_exchange_observer.get())

    def test_core_observer_ignores_worker_threads_and_operational_exchanges(self):
        def fixture(*args):
            worker=threading.Thread(target=module.exchange,args=(1,None,b'PRIVATE-REQUEST'))
            worker.start();worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
            module.exchange(1,None,b'PRIVATE-REQUEST')
            module.core_stage(None)
            module.exchange(1,None,b'PRIVATE-REQUEST')
            return args[-1].report()
        with patch.object(module,'_qualify',side_effect=fixture),patch.object(module,'_exchange',return_value=(200,b'PRIVATE-BODY')):
            result=module.qualify(None,None,None,None)
        self.assertEqual(result['exchanges_observed'],1)
        self.assertEqual(result['last_exchanges'][0]['stage'],'signed_fidelity')

    def test_initial_core_failure_is_retained_in_receipt_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp)/'source';output=Path(tmp)/'output';output.mkdir()
            sdk=root/'sdk/spring-boot';backend=root/'examples/spring-ingress/backend'
            for directory in (sdk,backend):
                (directory/'target').mkdir(parents=True)
                (directory/'pom.xml').write_text('<project/>')
            (sdk/'target/appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar').write_bytes(b'test-starter')
            (root/'examples/spring-ingress/ingress.py').write_text('# test ingress')
            with zipfile.ZipFile(backend/'target/spring-ingress-backend-0.1.0-SNAPSHOT.jar','w') as archive:
                archive.writestr('Example.class',b'test-class')
            def build(command,**kwargs):
                for argument in command:
                    if argument.startswith('-DoutputDirectory='):
                        (Path(argument.split('=',1)[1])/'appguard-spring-boot-starter-test.jar').write_bytes(b'test-starter')
                    elif argument.startswith('-DoutputFile='):
                        Path(argument.split('=',1)[1]).write_text('test dependency list')
            def git(command,**kwargs):
                return 'test-commit\n' if command[1]=='rev-parse' else b''
            children=[Mock(pid=value) for value in (101,102,103)]
            for child in children:child.poll.return_value=0
            signer=Mock(token='PRIVATE-TOKEN');signer.headers.return_value=[('Authorization','Bearer PRIVATE-TOKEN')]
            for name,value in {'ROOT':root,'source_hashes':lambda:{},'certificates':lambda *args:'PRIVATE-PASSWORD',
                    'Signer':lambda *args:signer,'wait_port':lambda *args:None,
                    'verify_redis_owner':lambda *args:'a'*40}.items():
                stack.enter_context(patch.object(module,name,value))
            stack.enter_context(patch.object(module.subprocess,'check_output',side_effect=git))
            stack.enter_context(patch.object(module.subprocess,'run',side_effect=build))
            stack.enter_context(patch.object(module.subprocess,'Popen',side_effect=children))
            stack.enter_context(patch.object(module.shutil,'copytree'))
            stack.enter_context(patch.object(module.ssl,'create_default_context',return_value=Mock()))
            client=stack.enter_context(patch('redis.Redis')).return_value
            stack.enter_context(patch.object(module,'_exchange',return_value=(504,b'{"code":"BACKEND_TIMEOUT"}')))
            with self.assertRaises(AssertionError):module.qualify(output,Path('maven'),Path('java'),Path('redis'))
            receipt=json.loads((output/'receipt.json').read_text())
            self.assertTrue(receipt['owned_process_cleanup'])
            self.assertFalse(receipt['checks']['signed_fidelity'])
            self.assertEqual(receipt['core_diagnostics']['exchanges_observed'],1)
            outcome=receipt['core_diagnostics']['last_exchanges'][0]
            self.assertEqual((outcome['stage'],outcome['status'],outcome['error_code']),('signed_fidelity',504,'BACKEND_TIMEOUT'))
            self.assertIsNone(outcome['exception_category'])
            self.assertGreaterEqual(client.close.call_count,1)
            self.assertIsNone(module._core_exchange_observer.get())
            self.assertNotIn('PRIVATE',json.dumps(receipt))

    def test_new_output_rejects_source_existing_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp).resolve()
            with self.assertRaises(ValueError):module.new_output(base)
            with self.assertRaises(ValueError):module.new_output(ROOT/'not-created')
            (base/'link').symlink_to(base,target_is_directory=True)
            with self.assertRaises(ValueError):module.new_output(base/'link/new')
            output=module.new_output(base/'fresh')
            self.assertEqual(output.stat().st_mode&0o777,0o700)

    def test_wire_preserves_raw_target_and_binary_body(self):
        target='/v1/items?x=%2f&x=%2F'
        value=module.wire(target,[('Signature','appguard=:EXAMPLE:')],b'\x00\xff')
        self.assertTrue(value.startswith(('POST '+target+' HTTP/1.1\r\n').encode()))
        self.assertTrue(value.endswith(b'\r\n\r\n\x00\xff'))
        self.assertIn(b'Content-Length: 2\r\n',value)
        self.assertNotIn(b'Transfer-Encoding:',value)

    def test_chunked_encoding_terminates_empty_and_nonempty(self):
        self.assertTrue(module.wire('/v1/items?',[],b'',True).endswith(b'\r\n\r\n0\r\n\r\n'))
        value=module.wire('/v1/items',[],b'abc',True)
        self.assertIn(b'Transfer-Encoding: chunked\r\n',value)
        self.assertNotIn(b'Content-Length:',value)
        self.assertTrue(value.endswith(b'3\r\nabc\r\n0\r\n\r\n'))

    def test_cleanup_only_signals_supplied_owned_child(self):
        child=Mock();child.poll.side_effect=[None,0]
        self.assertTrue(module.stop(child));child.terminate.assert_called_once();child.wait.assert_called_once_with(timeout=8)
        child.kill.assert_not_called()

    def test_cleanup_escalates_only_if_owned_child_does_not_settle(self):
        child=Mock();child.poll.side_effect=[None,-9]
        child.wait.side_effect=[subprocess.TimeoutExpired('owned',8),-9]
        self.assertTrue(module.stop(child));child.kill.assert_called_once()

    def test_cleanup_failure_does_not_skip_other_owned_children(self):
        first,second=object(),object()
        with patch.object(module,'stop',side_effect=[OSError('fixed test failure'),True]) as stop:
            self.assertFalse(module.cleanup([first,second]))
        self.assertEqual([call.args[0] for call in stop.call_args_list],[second,first])

    def test_counter_snapshot_rejects_unexpected_fields_or_boolean_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'counts.json'
            sample={key:0 for key in ('dispatch','auth','key','replay','resource')}
            path.write_text(json.dumps(sample));self.assertEqual(module.counters(path),sample)
            sample['dispatch']=True;path.write_text(json.dumps(sample))
            with self.assertRaises(AssertionError):module.counters(path)

    def test_export_hashes_metadata_and_rejects_unrecorded_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            for name in ('example.jar','_remote.repositories','maven-metadata-local.xml'):
                (directory/name).write_bytes(name.encode())
            hashes=module.file_hashes(directory)
            self.assertEqual(set(hashes),{'example.jar','_remote.repositories','maven-metadata-local.xml'})
            module.verify_pins({},directory,hashes)
            (directory/'unrecorded').write_bytes(b'new')
            with self.assertRaises(AssertionError):module.verify_pins({},directory,hashes)

    def test_provenance_rejects_changed_source_and_exported_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);tree=base/'runtime';tree.mkdir()
            source=base/'source.py';source.write_bytes(b'original')
            metadata=tree/'_remote.repositories';metadata.write_bytes(b'original')
            pins={source:module.digest(source)};hashes=module.file_hashes(tree)
            source.write_bytes(b'changed')
            with self.assertRaises(AssertionError):module.verify_pins(pins,tree,hashes)
            source.write_bytes(b'original');metadata.write_bytes(b'changed')
            with self.assertRaises(AssertionError):module.verify_pins(pins,tree,hashes)

    def test_export_rejects_symlink_files_and_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);tree=base/'runtime';tree.mkdir();file=base/'outside';file.write_bytes(b'value')
            (tree/'link').symlink_to(file)
            with self.assertRaises(AssertionError):module.file_hashes(tree)
            (tree/'link').unlink();(tree/'link').symlink_to(base,target_is_directory=True)
            with self.assertRaises(AssertionError):module.file_hashes(tree)


class OperationalTests(unittest.TestCase):
    def test_soak_options_reject_unbounded_or_noninteger_work(self):
        for seconds, concurrency in ((-1,8),(3601,8),(True,8),(1,0),(1,33),(1,True),(1.5,8)):
            with self.subTest(seconds=seconds,concurrency=concurrency):
                with self.assertRaises(ValueError):module.validate_soak_options(seconds,concurrency)
        module.validate_soak_options(0,8)
        module.validate_soak_options(1,1)
        module.validate_soak_options(3600,32)

    def test_invalid_soak_cli_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp).resolve()/'never-created'
            result=subprocess.run([sys.executable,str(ROOT/'scripts/qualification/spring_ingress.py'),
                '--output',str(output),'--soak-seconds','3601','--java-home',sys.prefix,
                '--maven',sys.executable,'--redis-server',sys.executable],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'SPRING_QUALIFICATION_FAILED',result.stderr)
            self.assertFalse(output.exists())

    def test_fault_control_rejects_foreign_child_and_changed_run_binding(self):
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for owners,run_id in (({},'owned-run'),({child:(child.pid,'different-run')},'owned-run'),
                                  ({child:(child.pid+1,'owned-run')},'owned-run')):
                with self.assertRaises(AssertionError):module.stop_owned(child,owners,run_id)
                self.assertIsNone(child.poll())
            self.assertTrue(module.stop_owned(child,{child:(child.pid,'owned-run')},'owned-run'))
            self.assertIsNotNone(child.poll())
        finally:
            module.cleanup([child])

    def test_redis_fault_identity_requires_both_owned_pid_and_server_run_id(self):
        child=Mock(pid=123);child.poll.return_value=None
        client=Mock();client.info.return_value={'process_id':123,'run_id':'a'*40}
        self.assertEqual(module.verify_redis_owner(client,child,{child:(123,'owned-run')},'owned-run'), 'a'*40)
        for info,expected in (({'process_id':999,'run_id':'a'*40},None),
                ({'process_id':123,'run_id':'b'*40},'a'*40),({'process_id':123,'run_id':'malformed'},None)):
            client.info.return_value=info
            with self.assertRaises(AssertionError):module.verify_redis_owner(client,child,{child:(123,'owned-run')},'owned-run',expected)

    def test_latency_metrics_bound_memory_and_reject_nonfinite_samples(self):
        stats=module.LatencyMetrics()
        for value in (.001,.002,.003,.100):stats.observe(value)
        result=stats.report()
        self.assertEqual(result['samples'],4)
        self.assertEqual(sum(result['histogram_counts']),4)
        self.assertAlmostEqual(result['mean_ms'],26.5)
        self.assertAlmostEqual(result['max_ms'],100)
        self.assertEqual(result['p95_upper_bound_ms'],100)
        for value in (float('nan'),float('inf'),-1,True):
            with self.assertRaises(ValueError):stats.observe(value)

    def test_outcome_counts_distinguish_timeout_replay_and_unknown_error_without_private_data(self):
        stats=module.OutcomeMetrics()
        stats.observe('normal',(504,b'{"code":"BACKEND_TIMEOUT"}'))
        stats.observe('normal',(504,b'{"code":"BACKEND_TIMEOUT"}'))
        stats.observe('replay',(403,b'{"code":"REPLAY_DETECTED"}'))
        stats.observe('replay',(403,b'{"code":"PRIVATE-CODE","secret":"PRIVATE-BODY"}'))
        result=stats.report()
        self.assertEqual(result['normal']['statuses'],[{'status':504,'count':2}])
        self.assertEqual(result['normal']['error_codes']['BACKEND_TIMEOUT'],2)
        self.assertEqual(result['replay']['statuses'],[{'status':403,'count':2}])
        self.assertEqual(result['replay']['error_codes']['REPLAY_DETECTED'],1)
        self.assertEqual(result['replay']['unrecognized_error_body'],1)
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_outcome_counts_bound_status_and_body_classification(self):
        stats=module.OutcomeMetrics()
        for status in (True,99,600,'PRIVATE-STATUS'):
            stats.observe('normal',(status,b'PRIVATE-BODY'))
        stats.observe('normal',(None,b'PRIVATE-BODY'))
        for body in (b'{"code":"PRIVATE-CODE"}',b'['*300,b'{"code":"BACKEND_TIMEOUT","x":"PRIVATE"}'):
            stats.observe('normal',(503,body))
        stats.transport_error('replay')
        result=stats.report()
        self.assertEqual(result['normal']['invalid_status'],4)
        self.assertEqual(result['normal']['missing_status'],1)
        self.assertEqual(result['normal']['statuses'],[{'status':503,'count':3}])
        self.assertEqual(result['normal']['unrecognized_error_body'],3)
        self.assertEqual(result['replay']['transport_errors'],1)
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(set(result),{'schema','normal','replay'})
        self.assertTrue(all(type(value) is int for value in result['normal']['error_codes'].values()))

    def test_soak_detects_response_fidelity_and_replay_acceptance_failures(self):
        class Signer:
            def headers(self,target,body):return []
        with patch.object(module,'exchange',new=lambda *args:(200,b'wrong-entity')):
            result=module.run_soak(1,2,1,None,Signer())
        self.assertGreater(result['signed_requests'],0)
        self.assertEqual(result['fidelity_failures'],result['signed_requests'])
        self.assertEqual(result['replay_failures'],result['replay_requests'])
        self.assertGreaterEqual(result['elapsed_seconds'],1)
        self.assertLess(result['elapsed_seconds'],3)
        self.assertTrue(all(math.isfinite(result[key]) for key in ('elapsed_seconds','requests_per_second','error_rate')))
        with self.assertRaises(AssertionError):module.require_soak_success(result)

    def test_soak_records_transport_errors_without_exception_text(self):
        class Signer:
            def headers(self,target,body):return []
        with patch.object(module,'exchange',side_effect=OSError('private-token-and-body')):
            result=module.run_soak(1,1,1,None,Signer())
        self.assertGreater(result['transport_errors'],0)
        self.assertEqual(result['outcomes']['normal']['transport_errors'],result['signed_requests'])
        self.assertEqual(result['outcomes']['replay']['transport_errors'],result['replay_requests'])
        self.assertNotIn('private-token',json.dumps(result))
        with self.assertRaises(AssertionError):module.require_soak_success(result)

    def test_soak_requires_counter_deltas_for_every_signed_and_replayed_request(self):
        before={'dispatch':8,'auth':8,'key':8,'replay':8,'resource':7}
        after={'dispatch':14,'auth':14,'key':14,'replay':14,'resource':10}
        soak={'signed_requests':3,'replay_requests':3}
        self.assertEqual(module.verify_soak_counters(before,after,soak),
            {'dispatch':6,'auth':6,'key':6,'replay':6,'resource':3})
        for changed in (after|{'resource':13},after|{'replay':13},after|{'dispatch':0}):
            with self.assertRaises(AssertionError):module.verify_soak_counters(before,changed,soak)

    def test_soak_cancels_workers_when_resource_sampling_fails(self):
        class Signer:
            def headers(self,target,body):return []
        def response(*args):
            time.sleep(.01)
            return 200,b'wrong'
        def unavailable():raise OSError('resource-snapshot-unavailable')
        started=time.monotonic()
        with patch.object(module,'exchange',new=response):
            with self.assertRaises(OSError):module.run_soak(2,2,1,None,Signer(),unavailable)
        self.assertLess(time.monotonic()-started,.6)

    def test_soak_counts_healthy_cycles_and_checks_each_exact_replay(self):
        class Signer:
            def headers(self,target,body):return []
        local=threading.local()
        def response(port,context,request):
            time.sleep(.002)
            if getattr(local,'last',None)==request:
                local.last=None
                return 403,b'{"code":"REPLAY_DETECTED"}'
            local.last=request
            return 200,request.split(b'\r\n\r\n',1)[1]
        with patch.object(module,'exchange',new=response):
            result=module.run_soak(1,2,1,None,Signer())
        module.require_soak_success(result)
        self.assertGreater(result['signed_requests'],1)
        self.assertEqual(result['latency']['samples'],result['signed_requests']*2)
        self.assertEqual(result['error_rate'],0)
        self.assertEqual(result['outcomes']['normal']['statuses'],[{'status':200,'count':result['signed_requests']}])
        self.assertEqual(result['outcomes']['replay']['error_codes']['REPLAY_DETECTED'],result['replay_requests'])

    def test_redis_outage_requires_specific_deny_and_bounded_latency(self):
        request=b'private-request'
        for response in ((200,b'private-request'),(503,b'{"code":"OTHER_FAILURE"}'),(502,b'')):
            with patch.object(module,'exchange',return_value=response):
                with self.assertRaises(AssertionError):module.expect_redis_unavailable(1,None,request)
        with patch.object(module,'exchange',return_value=(503,b'{"code":"REPLAY_STORE_UNAVAILABLE"}')):
            self.assertGreaterEqual(module.expect_redis_unavailable(1,None,request),0)
            with patch.object(module.time,'monotonic',side_effect=[0.,4.]):
                with self.assertRaises(AssertionError):module.expect_redis_unavailable(1,None,request)

    def test_process_resources_report_only_numeric_owned_process_measurements(self):
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            result=module.process_resources({'owned_child':child})
            self.assertEqual(set(result),{'owned_child'})
            self.assertEqual(set(result['owned_child']),{'pid','rss_bytes','cpu_seconds'})
            self.assertEqual(result['owned_child']['pid'],child.pid)
            self.assertGreater(result['owned_child']['rss_bytes'],0)
            self.assertGreaterEqual(result['owned_child']['cpu_seconds'],0)
        finally:module.cleanup([child])


if __name__=='__main__':unittest.main()
