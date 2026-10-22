#!/usr/bin/env python3
"""Actual local TLS/mTLS qualification. Never connects to an operator Redis URL.

Private ephemeral keys/logs stay in an owned temporary directory. The retained
receipt proves this local topology only, not a production deployment or audit.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CHECKS = ('signed_fidelity', 'replay_rejected', 'backend_bypass_rejected',
          'absolute_upload_deadline', 'malformed_framing_rejected',
          'backend_failure_bounded', 'healthy_recovery', 'owned_process_cleanup')


def require(condition):
    if not condition:
        raise AssertionError('qualification invariant failed')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def file_hashes(directory):
    """Include metadata as well as JARs; reject links and special files."""
    import stat
    directory=Path(directory)
    require(directory.is_dir() and not directory.is_symlink())
    result={}
    for path in sorted(directory.rglob('*')):
        mode=path.lstat().st_mode
        require(not stat.S_ISLNK(mode))
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode))
        result[str(path.relative_to(directory))]=digest(path)
    return result


def verify_pins(paths, tree, expected_tree):
    require(file_hashes(tree)==expected_tree)
    for path, expected in paths.items():
        require(not path.is_symlink() and path.is_file() and digest(path)==expected)


def source_hashes():
    paths=[ROOT/'sdk/spring-boot/pom.xml',ROOT/'examples/spring-ingress/backend/pom.xml',
           ROOT/'examples/spring-ingress/ingress.py',Path(__file__).resolve()]
    for directory in ('sdk/spring-boot/src/main','examples/spring-ingress/backend/src', 'sdk/python/src/appguard'):
        base=ROOT/directory
        paths.extend(base/name for name in file_hashes(base) if '__pycache__' not in Path(name).parts and not name.endswith('.pyc'))
    return {path:digest(path) for path in paths}


def new_output(value):
    path = Path(value).absolute()
    if path != path.resolve() or path.exists() or ROOT == path or ROOT in path.parents:
        raise ValueError('new canonical output outside source tree required')
    if not path.parent.is_dir() or any(p.is_symlink() for p in (path.parent, *path.parents)):
        raise ValueError('unsafe output parent')
    path.mkdir(mode=0o700)
    return path


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.poll() is not None


def cleanup(processes):
    settled=True
    for process in reversed(processes):
        try:
            settled=stop(process) and settled
        except (OSError, subprocess.TimeoutExpired):
            # A failed shutdown must not skip cleanup of the remaining children.
            settled=False
    return settled


def wait_port(process, port, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        require(process.poll() is None)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError('owned listener did not start')



def validate_soak_options(seconds, concurrency):
    if type(seconds) is not int or not 0 <= seconds <= 3600 or type(concurrency) is not int or not 1 <= concurrency <= 32:
        raise ValueError('bounded integer soak options required')


def stop_owned(process, owners, run_id):
    # Popen.poll checks this exact child before a signal; never signal a PID read
    # from a socket or accept a child from another qualification run.
    require(owners.get(process)==(process.pid,run_id) and process.poll() is None)
    return stop(process)


def verify_redis_owner(client, process, owners, run_id, expected_run_id=None):
    require(owners.get(process)==(process.pid,run_id) and process.poll() is None)
    info=client.info('server')
    identity=info.get('run_id')
    require(info.get('process_id')==process.pid and type(identity) is str and re.fullmatch('[0-9a-f]{40}',identity) is not None)
    require(expected_run_id is None or identity==expected_run_id)
    return identity


class LatencyMetrics:
    # Fixed buckets keep memory independent of request count and soak duration.
    bounds=(1,2,5,10,20,50,100,200,500,1000,2000,5000,10000)

    def __init__(self):
        self.counts=[0]*(len(self.bounds)+1)
        self.samples=0;self.total=0.;self.minimum=None;self.maximum=0.

    def observe(self,seconds):
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds<0:
            raise ValueError('finite nonnegative latency required')
        milliseconds=seconds*1000
        if not math.isfinite(milliseconds):
            raise ValueError('finite latency required')
        index=next((i for i,bound in enumerate(self.bounds) if milliseconds<=bound),len(self.bounds))
        self.counts[index]+=1;self.samples+=1;self.total+=milliseconds
        self.minimum=milliseconds if self.minimum is None else min(self.minimum,milliseconds)
        self.maximum=max(self.maximum,milliseconds)

    def merge(self,other):
        self.counts=[a+b for a,b in zip(self.counts,other.counts)]
        self.samples+=other.samples;self.total+=other.total
        if other.minimum is not None:
            self.minimum=other.minimum if self.minimum is None else min(self.minimum,other.minimum)
        self.maximum=max(self.maximum,other.maximum)

    def report(self):
        def percentile(fraction):
            accumulated=0
            for index,count in enumerate(self.counts):
                accumulated+=count
                if accumulated>=max(1,math.ceil(self.samples*fraction)):
                    return min(self.bounds[index],self.maximum) if index<len(self.bounds) else self.maximum
            return 0.
        return {'samples':self.samples,'min_ms':self.minimum or 0.,'max_ms':self.maximum,
            'mean_ms':self.total/self.samples if self.samples else 0.,
            'p50_upper_bound_ms':percentile(.5),'p95_upper_bound_ms':percentile(.95),'p99_upper_bound_ms':percentile(.99),
            'histogram_upper_bounds_ms':list(self.bounds),'histogram_counts':self.counts.copy()}


def process_resources(processes):
    """Point-in-time RSS and cumulative CPU only; no command/env disclosure."""
    result={}
    for role,process in processes.items():
        require(process.poll() is None)
        output=subprocess.check_output(['ps','-o','pid=,rss=,time=','-p',str(process.pid)],text=True,timeout=2)
        require(len(output)<256)
        fields=output.split();require(len(fields)==3 and fields[0]==str(process.pid))
        rss=int(fields[1])*1024
        match=re.fullmatch(r'(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)',fields[2])
        require(match is not None)
        days,hours,minutes,seconds=match.groups()
        cpu=int(days or 0)*86400+int(hours or 0)*3600+int(minutes)*60+float(seconds)
        require(rss>=0 and math.isfinite(cpu) and cpu>=0)
        result[role]={'pid':process.pid,'rss_bytes':rss,'cpu_seconds':cpu}
    return result


def replay_denied(response):
    status,body=response
    try:
        return status==403 and json.loads(body)=={'code':'REPLAY_DETECTED'}
    except (ValueError,UnicodeError):
        return False


def run_soak(seconds, concurrency, port, context, signer, sample_resources=None):
    validate_soak_options(seconds,concurrency);require(seconds>0)
    started=time.monotonic();deadline=started+seconds;cancel=threading.Event()
    def worker(index):
        metrics={name:0 for name in ('signed_requests','replay_requests','fidelity_failures','replay_failures','transport_errors')}
        latency=LatencyMetrics()
        while not cancel.is_set() and time.monotonic()<deadline:
            target='/v1/items?worker='+str(index)+'&x=%2f&x=%2F'
            body=b'\x00\xff\r\n'+secrets.token_bytes(32)
            request=wire(target,signer.headers(target,body),body)
            for replay in (False,True):
                metrics['replay_requests' if replay else 'signed_requests']+=1
                begin=time.monotonic()
                try:
                    response=exchange(port,context,request)
                    if replay:
                        metrics['replay_failures']+=not replay_denied(response)
                    else:
                        metrics['fidelity_failures']+=response!=(200,body)
                except (OSError,ValueError):
                    metrics['transport_errors']+=1
                finally:
                    latency.observe(time.monotonic()-begin)
            # Avoid unbounded hot spinning if a local endpoint fails immediately.
            if metrics['transport_errors']:
                time.sleep(.01)
        return metrics,latency
    result={name:0 for name in ('signed_requests','replay_requests','fidelity_failures','replay_failures','transport_errors')}
    latency=LatencyMetrics()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        pending={pool.submit(worker,index) for index in range(concurrency)}
        try:
            while pending:
                if sample_resources is not None:sample_resources()
                finished,pending=wait(pending,timeout=1)
                for future in finished:
                    metrics,samples=future.result()
                    for name,value in metrics.items():result[name]+=value
                    latency.merge(samples)
        finally:
            cancel.set()
    elapsed=time.monotonic()-started
    requests=result['signed_requests']+result['replay_requests']
    errors=result['fidelity_failures']+result['replay_failures']+result['transport_errors']
    return result|{'requested_seconds':seconds,'concurrency':concurrency,'elapsed_seconds':elapsed,
        'requests_per_second':requests/elapsed,'error_rate':errors/requests if requests else 1.,'latency':latency.report()}


def require_soak_success(result):
    require(result['signed_requests']>0 and result['signed_requests']==result['replay_requests']
        and result['elapsed_seconds']>=result['requested_seconds']
        and all(result[name]==0 for name in ('fidelity_failures','replay_failures','transport_errors')))



def verify_soak_counters(before,after,soak):
    delta={name:after[name]-value for name,value in before.items()}
    requests=soak['signed_requests']+soak['replay_requests']
    require(delta=={'dispatch':requests,'auth':requests,'key':requests,'replay':requests,'resource':soak['signed_requests']})
    return delta


def expect_healthy(port,context,signer):
    body=secrets.token_bytes(32);target='/v1/items?recovery=%2f&recovery=%2F'
    request=wire(target,signer.headers(target,body),body)
    require(exchange(port,context,request)==(200,body))
    return request


def admission_probe(spawn,env,port,context,signer,count_file):
    pressure_port=free_port()
    gateway=spawn([sys.executable,str(ROOT/'examples/spring-ingress/ingress.py')],env|{
        'APPGUARD_LISTEN_PORT':str(pressure_port),'APPGUARD_MAX_CONNECTIONS':'4','APPGUARD_MAX_INFLIGHT':'2'},'pressure-gateway')
    wait_port(gateway,pressure_port)
    baseline=counters(count_file);holders=[]
    def connect():
        raw=socket.create_connection(('127.0.0.1',pressure_port),timeout=2)
        try:
            secured=context.wrap_socket(raw,server_hostname='api.example.test');secured.settimeout(7)
            return secured
        except BaseException:
            raw.close();raise
    started=time.monotonic()
    try:
        for _ in range(2):
            connection=connect();holders.append(connection)
            connection.sendall(b'POST /v1/items HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 8\r\n\r\n')
        # Let the event loop register both bounded body-capture applications.
        time.sleep(.1)
        response=exchange(pressure_port,context,wire('/v1/items',signer.headers('/v1/items',b'pressure'),b'pressure'))
        require(response[0]==503 and json.loads(response[1])=={'code':'INGRESS_OVERLOADED'})
        require(counters(count_file)==baseline)
    finally:
        for connection in holders:connection.close()
    overload_seconds=time.monotonic()-started
    require(overload_seconds<3.5)
    # A post-cancellation healthy request proves inflight admission is released.
    time.sleep(.9);expect_healthy(pressure_port,context,signer)
    baseline=counters(count_file);holders=[];started=time.monotonic()
    try:
        for _ in range(4):
            connection=connect();holders.append(connection)
            connection.sendall(b'POST /v1/items HTTP/1.1\r\nHost: api.example.test\r\n')
        refused=False
        try:
            # A fifth TLS connection must be refused by the raw admission cap.
            with connect() as extra:
                extra.sendall(b'POST /v1/items HTTP/1.1\r\n')
                refused=extra.recv(1)==b''
        except (ConnectionError,ssl.SSLError):
            refused=True
        require(refused)
        for connection in holders:
            try:require(connection.recv(1)==b'')
            except (ConnectionError,ssl.SSLError):pass
        require(time.monotonic()-started<7 and counters(count_file)==baseline)
    finally:
        for connection in holders:connection.close()
    header_seconds=time.monotonic()-started
    expect_healthy(pressure_port,context,signer);expect_healthy(port,context,signer)
    return {'passed':True,'max_connections':4,'max_inflight':2,'slow_header_connections':4,
        'overload_status':503,'overload_seconds':overload_seconds,'excess_connection_refused':1,
        'slow_header_close_seconds':header_seconds,'recovered':True,
        'counters_before_slow_headers':baseline,'counters_after_recovery':counters(count_file)}



def expect_redis_unavailable(port,context,request):
    started=time.monotonic()
    response=exchange(port,context,request)
    elapsed=time.monotonic()-started
    require(response[0]==503 and json.loads(response[1])=={'code':'REPLAY_STORE_UNAVAILABLE'} and elapsed<3.5)
    return elapsed


def operational_probes(report,seconds,concurrency,spawn,owners,run_id,owned,client,redis_run_id,redis_command,
                       backend_command,backend_env,env,gateway_env,gateway_port,context,signer,count_file):
    resources={'scope':'primary Redis/backend/ingress child ps RSS and cumulative CPU; sampled points only; excludes build and pressure/failure gateways; not leak proof',
        'samples':0,'peak_rss_bytes':{role:0 for role in owned}}
    def sample():
        current=process_resources(owned);resources['samples']+=1
        for role,value in current.items():resources['peak_rss_bytes'][role]=max(resources['peak_rss_bytes'][role],value['rss_bytes'])
        return current
    report['resources']=resources;resources['before']=sample()
    report['counters']={'before_faults':counters(count_file),'scope':'backend process-local counters; reset on backend restart'}
    # Authenticate the listener against the exact spawned child AND Redis run ID
    # immediately before fault control. This fixture never uses shared Redis.
    verify_redis_owner(client,owned['redis'],owners,run_id,redis_run_id)
    before=counters(count_file)
    require(stop_owned(owned['redis'],owners,run_id))
    body=secrets.token_bytes(32);target='/v1/items'
    request=wire(target,signer.headers(target,body),body)
    report['redis_outage']={'deny_status':503,'deny_seconds':expect_redis_unavailable(gateway_port,context,request)}
    require(counters(count_file)['resource']==before['resource'])
    report['checks']['redis_outage_denied']=True
    owned['redis']=spawn(redis_command,env,'redis-restarted');wait_port(owned['redis'],client.connection_pool.connection_kwargs['port'])
    replacement_id=verify_redis_owner(client,owned['redis'],owners,run_id)
    require(replacement_id!=redis_run_id)
    started=time.monotonic()
    # Each trial is newly signed, never a retry of a possibly consumed nonce.
    recovered=False;attempts=0
    while time.monotonic()-started<15:
        attempts+=1
        body=secrets.token_bytes(32);request=wire(target,signer.headers(target,body),body)
        response=exchange(gateway_port,context,request)
        if response==(200,body):recovered=True;break
        require(response[0]==503 and json.loads(response[1])=={'code':'REPLAY_STORE_UNAVAILABLE'})
        time.sleep(.25)
    report['redis_recovery']={'recovered':recovered,'attempts':attempts,'seconds':time.monotonic()-started,
        'new_owned_server_run':True,'automatic_recovery':recovered,'persistence_enabled':False,'replay_retention_across_redis_loss_verified':False}
    require(recovered and report['redis_recovery']['seconds']<=15)
    require(replay_denied(exchange(gateway_port,context,request)))
    report['redis_recovery']['new_replay_rejected']=True
    report['checks']['redis_recovered']=True
    # Keep Redis running, then prove its replay claim survives a backend restart.
    replay=expect_healthy(gateway_port,context,signer)
    require(replay_denied(exchange(gateway_port,context,replay)))
    report['counters']['before_backend_restart']=counters(count_file)
    verify_redis_owner(client,owned['redis'],owners,run_id,replacement_id)
    require(stop_owned(owned['backend'],owners,run_id))
    started=time.monotonic()
    request=wire(target,signer.headers(target,b'bounded'),b'bounded')
    require(exchange(gateway_port,context,request)[0] in {502,504} and time.monotonic()-started<3.5)
    # Startup requires a new empty owner-only counter file. Snapshot is retained
    # above; clear it only after the exact owned backend has fully stopped.
    count_file.write_bytes(b'')
    owned['backend']=spawn(backend_command,backend_env,'backend-restarted')
    wait_port(owned['backend'],int(backend_env['APPGUARD_BACKEND_PORT']),60)
    expect_healthy(gateway_port,context,signer)
    require(replay_denied(exchange(gateway_port,context,replay)))
    verify_redis_owner(client,owned['redis'],owners,run_id,replacement_id)
    report['backend_restart']={'recovered':True,'replay_retained':True,'seconds':time.monotonic()-started,
        'redis_run_unchanged':True,'counter_reset_expected':True}
    report['checks']['backend_restarted_with_replay_retained']=True
    report['counters']['after_backend_restart']=counters(count_file)
    report['admission']=admission_probe(spawn,gateway_env,gateway_port,context,signer,count_file)
    report['checks']['admission_pressure_recovered']=True
    resources['after_recovery']=sample()
    report['counters']['after_recovery']=counters(count_file)
    # Create restart replay evidence first, within the request's 60-second
    # acceptance window; a long soak must never age that proof into INVALID_TIME.
    report['counters']['before_soak']=counters(count_file)
    report['soak']=run_soak(seconds,concurrency,gateway_port,context,signer,sample)
    report['counters']['after_soak']=counters(count_file)
    resources['after_soak']=sample();require_soak_success(report['soak'])
    report['counters']['soak_delta']=verify_soak_counters(report['counters']['before_soak'],report['counters']['after_soak'],report['soak'])
    report['checks']['soak']=True
    report['passed']=True


def certificates(directory, java_home):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.now(timezone.utc)
    def issue(name, issuer=None, client=False):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        parent_key, parent = issuer if issuer else (key, None)
        builder = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(parent.subject if parent else subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
            .not_valid_after(now+timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None), True))
        if issuer:
            builder = builder.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
            if not client:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        cert = builder.sign(parent_key, hashes.SHA256())
        cert_path, key_path = directory/(name+'.pem'), directory/(name+'.key')
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return key, cert
    server_ca = issue('server-ca')
    client_ca = issue('client-ca')
    issue('api.example.test', server_ca)
    backend = issue('backend.example.test', server_ca)
    issue('ingress-client', client_ca, True)
    wrong_ca = issue('wrong-ca')
    issue('wrong-client', wrong_ca, True)
    password = secrets.token_urlsafe(24)
    (directory/'backend.p12').write_bytes(pkcs12.serialize_key_and_certificates(
        b'backend', backend[0], backend[1], [server_ca[1]], serialization.BestAvailableEncryption(password.encode())))
    (directory/'backend.p12').chmod(0o600)
    # Java trusted-certificate entries require keytool rather than a bag-only p12.
    subprocess.run([str(java_home/'bin/keytool'), '-importcert', '-noprompt', '-alias', 'ingress-ca',
        '-file', str(directory/'client-ca.pem'), '-keystore', str(directory/'trust.p12'),
        '-storetype', 'PKCS12', '-storepass', password], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (directory/'trust.p12').chmod(0o600)
    return password


class Signer:
    def __init__(self, directory):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.token = secrets.token_urlsafe(32)
        (directory/'enrolled.pem').write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def headers(self, target, body):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from appguard.canonical import build_signature_base
        from appguard.types import RequestInput, SignatureParameters
        now = int(time.time())
        params = SignatureParameters(now, now+60, base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('='),
                                     'qualification-key', 'ecdsa-p256-sha256', 'appguard-request-v0')
        pairs = (('Content-Type', 'application/octet-stream'),
            ('Content-Digest', 'sha-256=:'+base64.b64encode(hashlib.sha256(body).digest()).decode()+':'),
            ('Authorization', 'Bearer '+self.token), ('AppGuard-App-Id', 'qualification-app'))
        base = build_signature_base(RequestInput('POST', target, pairs, body), params, origin='https://api.example.test')
        r, s = utils.decode_dss_signature(self.key.sign(base, ec.ECDSA(hashes.SHA256())))
        signature = base64.b64encode(r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode()
        return list(pairs)+[('Signature-Input', 'appguard='+base.decode().split('"@signature-params": ',1)[1]),
                            ('Signature', 'appguard=:'+signature+':')]


def wire(target, headers, body, chunked=False):
    fields = [('Host','api.example.test'), *headers,
              ('Transfer-Encoding','chunked') if chunked else ('Content-Length',str(len(body))), ('Connection','close')]
    payload = (f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n') if chunked and body else (b'0\r\n\r\n' if chunked else body)
    return b'POST '+target.encode('ascii')+b' HTTP/1.1\r\n'+b''.join(k.encode()+b': '+v.encode()+b'\r\n' for k,v in fields)+b'\r\n'+payload


def exchange(port, context, data, hostname='api.example.test', drip=None):
    import h11
    with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            connection.settimeout(4)
            if drip:
                head, body = data.split(b'\r\n\r\n', 1)
                connection.sendall(head+b'\r\n\r\n')
                for part in body:
                    try:
                        connection.sendall(bytes([part]))
                    except OSError:
                        break
                    time.sleep(drip)
            else:
                connection.sendall(data)
            parser = h11.Connection(h11.CLIENT)
            # Register the outgoing request so the parser permits a response.
            parser.send(h11.Request(method='POST',target='/',headers=[('Host','api.example.test')]))
            parser.send(h11.EndOfMessage())
            status, body = None, bytearray()
            while True:
                event = parser.next_event()
                if event is h11.NEED_DATA:
                    incoming = connection.recv(65536)
                    if not incoming:
                        return status, bytes(body)
                    parser.receive_data(incoming)
                elif isinstance(event,h11.Response):
                    status = event.status_code
                elif isinstance(event,h11.Data):
                    body.extend(event.data)
                    require(len(body)<=1048576)
                elif isinstance(event,(h11.EndOfMessage,h11.ConnectionClosed)):
                    return status, bytes(body)


def counters(path):
    for _ in range(100):
        try:
            result=json.loads(path.read_text())
            require(set(result)=={'dispatch','auth','key','replay','resource'})
            require(all(type(v) is int and v>=0 for v in result.values()))
            return result
        except (json.JSONDecodeError, OSError):
            time.sleep(.01)
    raise AssertionError('counter snapshot unavailable')


def qualify(output, maven, java_home, redis_server, soak_seconds=0, soak_concurrency=8):
    validate_soak_options(soak_seconds,soak_concurrency)
    import redis
    started=datetime.now(timezone.utc)
    receipt={'schema':1,'evidence_class':'local_deployment','profile':'spring-mtls-store-forward-v1',
        'candidate_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'observed_at':started.isoformat().replace('+00:00','Z'),
        'checks':{name:False for name in CHECKS},'release_ready':False,
        'limits':{'body_bytes':1048576,'upload_seconds':.8,'backend_seconds':2},
        'limitations':['local topology only','no external audit or provider validation','no physical device proof']}
    if soak_seconds:
        receipt['operational']={'schema':1,'passed':False,'release_ready':False,
            'scope':'actual local packaged Spring topology; synthetic owned traffic only',
            'checks':{name:False for name in ('soak','redis_outage_denied','redis_recovered',
                'backend_restarted_with_replay_retained','admission_pressure_recovered','owned_process_cleanup')},
            'limitations':['timed local soak is not long-term production or cloud operating proof',
                'Redis persistence disabled: restart discards replay state; production requires reviewed persistence and noeviction',
                'no external security review, provider-account validation, or production approval']}
    source_pins=source_hashes()
    receipt['source_sha256']={str(path.relative_to(ROOT)):value for path,value in source_pins.items()}
    receipt['source_matches_commit']=not bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT))
    pins={};runtime=None;hashes={}
    processes=[];owners={};run_id=secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='appguard-spring-qualification-') as temporary:
        private=Path(temporary).resolve();private.chmod(0o700)
        handles=[]
        client=None
        def spawn(command, env, name):
            handle=(private/(name+'.log')).open('wb');os.chmod(handle.name,0o600);handles.append(handle)
            process=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=handle,stderr=subprocess.STDOUT)
            processes.append(process);owners[process]=(process.pid,run_id);return process
        def run(command, name):
            with (private/(name+'.log')).open('wb') as log:
                os.chmod(log.name,0o600)
                subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
        env=os.environ.copy();env['JAVA_HOME']=str(java_home)
        env['PATH']=str(java_home/'bin')+os.pathsep+env.get('PATH','')
        env['PYTHONPATH']=str(ROOT/'sdk/python/src')
        try:
            # Copy the cache, never hardlink it: Maven may rewrite metadata.
            repository=private/'maven-repository'
            cache=Path.home()/'.m2/repository'
            if cache.is_dir():
                shutil.copytree(cache,repository,symlinks=False)
            else:
                repository.mkdir()
            shutil.rmtree(repository/'io/appguard',ignore_errors=True)
            sdk=ROOT/'sdk/spring-boot';backend=ROOT/'examples/spring-ingress/backend'
            common=[str(maven),'-B','-ntp','-Dmaven.repo.local='+str(repository)]
            run(common+['-f',str(sdk/'pom.xml'),'-DskipTests','package'],'sdk-build')
            sdk_jar=sdk/'target/appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar'
            run(common+['org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file',
                '-Dfile='+str(sdk_jar),'-DpomFile='+str(sdk/'pom.xml')],'sdk-install')
            runtime=output/'maven-runtime';runtime.mkdir()
            command=common+['-f',str(backend/'pom.xml'),'package',
                'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies',
                'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:list','-DincludeScope=runtime',
                '-Dmdep.useRepositoryLayout=true','-DoutputDirectory='+str(runtime),
                '-DoutputFile='+str(output/'maven-runtime-dependencies.txt'),'-DappendOutput=false']
            run(command,'backend-build')
            jars=sorted(runtime.rglob('*.jar'));require(jars and not any(p.is_symlink() for p in runtime.rglob('*')))
            hashes=file_hashes(runtime)
            jar_hashes={name:value for name,value in hashes.items() if name.endswith('.jar')}
            manifest={'returncode':0,'pom_sha256':digest(backend/'pom.xml'),'sha256':hashes,'jar_sha256':jar_hashes,
                'scope':'Actual Spring example runtime including embedded Servlet container; excludes test dependencies',
                'command':['maven','package','dependency:copy-dependencies','dependency:list','runtime-repository-layout']}
            (output/'maven-runtime-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
            shutil.copyfile(backend/'target/spring-ingress-backend-0.1.0-SNAPSHOT.jar',output/'backend.jar')
            with zipfile.ZipFile(output/'backend.jar') as archive:
                classes={name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist() if name.endswith('.class')}
            require(classes)
            receipt['exampleclasses_sha256']=classes
            receipt['artifact_sha256']={'sdk_jar':digest(sdk_jar),'example_pom':digest(backend/'pom.xml'),
                'ingress_source':digest(ROOT/'examples/spring-ingress/ingress.py')}
            receipt['sources']={'backend_jar':digest(output/'backend.jar')}
            require(any(digest(p)==receipt['artifact_sha256']['sdk_jar'] for p in jars if 'appguard-spring-boot-starter' in p.name))
            pins=source_pins|{path:digest(path) for path in (sdk_jar,output/'backend.jar',
                backend/'target/spring-ingress-backend-0.1.0-SNAPSHOT.jar',
                output/'maven-runtime-manifest.json',output/'maven-runtime-dependencies.txt')}
            verify_pins(pins,runtime,hashes)
            password=certificates(private,java_home);signer=Signer(private)
            redis_port,backend_port,gateway_port=free_port(),free_port(),free_port()
            redis_command=[str(redis_server),'--bind','127.0.0.1','--port',str(redis_port),'--save','','--appendonly','no','--dir',str(private)]
            redis_process=spawn(redis_command,env,'redis')
            wait_port(redis_process,redis_port)
            client=redis.Redis(host='127.0.0.1',port=redis_port,socket_connect_timeout=1,socket_timeout=1)
            redis_run_id=verify_redis_owner(client,redis_process,owners,run_id)
            count_file=private/'counters.json';count_file.touch(mode=0o600)
            backend_env=env|{'APPGUARD_BACKEND_PORT':str(backend_port),'APPGUARD_BACKEND_KEYSTORE':str(private/'backend.p12'),
                'APPGUARD_BACKEND_KEYSTORE_PASSWORD':password,'APPGUARD_BACKEND_TRUSTSTORE':str(private/'trust.p12'),
                'APPGUARD_BACKEND_TRUSTSTORE_PASSWORD':password,'APPGUARD_APP_ID':'qualification-app',
                'APPGUARD_ORIGIN':'https://api.example.test','APPGUARD_SUBJECT':'qualification-user','APPGUARD_KEY_ID':'qualification-key',
                'APPGUARD_PUBLIC_KEY_FILE':str(private/'enrolled.pem'),'APPGUARD_BEARER_SHA256':hashlib.sha256(signer.token.encode()).hexdigest(),
                'APPGUARD_REDIS_URL':f'redis://127.0.0.1:{redis_port}/0','APPGUARD_BACKEND_COUNTER_FILE':str(count_file)}
            classpath=os.pathsep.join(map(str,[output/'backend.jar',*jars]))
            backend_command=[str(java_home/'bin/java'),'-cp',classpath,'io.appguard.example.BackendMain']
            backend_process=spawn(backend_command,backend_env,'backend')
            wait_port(backend_process,backend_port,60)
            gateway_env=env|{'APPGUARD_ORIGIN':'https://api.example.test','APPGUARD_BACKEND_PORT':str(backend_port),
                'APPGUARD_BACKEND_HOSTNAME':'backend.example.test','APPGUARD_BACKEND_CA':str(private/'server-ca.pem'),
                'APPGUARD_BACKEND_CLIENT_CERT':str(private/'ingress-client.pem'),'APPGUARD_BACKEND_CLIENT_KEY':str(private/'ingress-client.key'),
                'APPGUARD_TLS_CERT':str(private/'api.example.test.pem'),'APPGUARD_TLS_KEY':str(private/'api.example.test.key'),
                'APPGUARD_LISTEN_HOST':'127.0.0.1','APPGUARD_LISTEN_PORT':str(gateway_port),
                'APPGUARD_BODY_TIMEOUT':'.8','APPGUARD_BACKEND_TIMEOUT':'2','APPGUARD_TOTAL_TIMEOUT':'5'}
            gateway=spawn([sys.executable,str(ROOT/'examples/spring-ingress/ingress.py')],gateway_env,'gateway')
            wait_port(gateway,gateway_port)
            context=ssl.create_default_context(cafile=str(private/'server-ca.pem'))
            direct=ssl.create_default_context(cafile=str(private/'server-ca.pem'))
            direct.load_cert_chain(private/'ingress-client.pem',private/'ingress-client.key')
            # The front endpoint must preserve every byte used by Spring's verifier.
            for target,body,chunked in [('/v1/items',b'\x00\xff\r\n',False),('/v1/items?x=1&x=2', '한글日本語'.encode(),False),
                    ('/v1/items?',b'',False),('/v1/items?x=%2f&y=%2F',b'chunked',True)]:
                require(exchange(gateway_port,context,wire(target,signer.headers(target,body),body,chunked))==(200,body))
            receipt['checks']['signed_fidelity']=True
            request=wire('/v1/items',signer.headers('/v1/items',b'replay'),b'replay')
            require(exchange(gateway_port,context,request)==(200,b'replay'))
            status,rejection=exchange(gateway_port,context,request)
            require(status==403 and json.loads(rejection)=={'code':'REPLAY_DETECTED'})
            receipt['checks']['replay_rejected']=True
            baseline=counters(count_file)
            for ctx,hostname in [(context,'backend.example.test'),(direct,'wrong.example.test')]:
                try:
                    result=exchange(backend_port,ctx,request,hostname)
                    require(result[0] is None)
                except (OSError,ssl.SSLError):
                    pass
            wrong=ssl.create_default_context(cafile=str(private/'server-ca.pem'))
            wrong.load_cert_chain(private/'wrong-client.pem',private/'wrong-client.key')
            try:
                require(exchange(backend_port,wrong,request,'backend.example.test')[0] is None)
            except (OSError,ssl.SSLError):
                pass
            with socket.create_connection(('127.0.0.1',backend_port),timeout=2) as raw:
                raw.settimeout(2);raw.sendall(request)
                try:
                    require(b'200' not in raw.recv(100))
                except (OSError,TimeoutError):
                    pass
            require(counters(count_file)==baseline)
            receipt['checks']['backend_bypass_rejected']=True
            body=b'12345678';target='/v1/items'
            request=wire(target,signer.headers(target,body),body)
            require(exchange(backend_port,direct,request,'backend.example.test',drip=.25)==(200,body))
            baseline=counters(count_file);keys=client.dbsize();begin=time.monotonic()
            request=wire(target,signer.headers(target,body),body)
            require(exchange(gateway_port,context,request,drip=.25)[0] in {408,504})
            require(time.monotonic()-begin<3.5)
            # An incomplete upload that never sends another byte also expires.
            head=request.split(b'\r\n\r\n',1)[0]+b'\r\n\r\n'
            require(exchange(gateway_port,context,head)[0] in {408,504})
            require(counters(count_file)==baseline and client.dbsize()==keys)
            receipt['checks']['absolute_upload_deadline']=True
            malformed=[request.replace(b'Signature: ',b'Signature: appguard=:AAAA:\r\nSignature: ',1),
                request.replace(b'Content-Length: 8',b'Content-Length: 8\r\nContent-Length: 8'),
                request.replace(b'Content-Length: 8',b'Content-Length: 8\r\nTransfer-Encoding: chunked'),
                request.replace(b'\r\n',b'\n'),request.replace(b'Content-Type:',b' Content-Type:',1),
                request.replace(b'Host: api.example.test',b'Host: api.example.test\r\nForwarded: for=127.0.0.1'),
                wire(target,signer.headers(target,body),body,True).replace(b'0\r\n\r\n',b'0\r\nX-Trailer: forbidden\r\n\r\n')]
            for attack in malformed:
                try:
                    require(exchange(gateway_port,context,attack)[0] in {None,400,408,413,431,504})
                except (OSError,ssl.SSLError):
                    pass
            require(counters(count_file)==baseline and client.dbsize()==keys)
            receipt['checks']['malformed_framing_rejected']=True
            # A separate gateway targets an owned, immediately closed port.
            failure_port=free_port();unavailable_port=free_port()
            failure=spawn([sys.executable,str(ROOT/'examples/spring-ingress/ingress.py')],gateway_env|{
                'APPGUARD_LISTEN_PORT':str(failure_port),'APPGUARD_BACKEND_PORT':str(unavailable_port)},'failure-gateway')
            wait_port(failure,failure_port)
            begin=time.monotonic()
            require(exchange(failure_port,context,wire(target,signer.headers(target,body),body))[0] in {502,504})
            require(time.monotonic()-begin<3.5 and counters(count_file)==baseline)
            receipt['checks']['backend_failure_bounded']=True
            require(exchange(gateway_port,context,wire(target,signer.headers(target,body),body))==(200,body))
            receipt['checks']['healthy_recovery']=True
            receipt['metrics']={'runtime_jars':len(jars),'backend_counters':counters(count_file)}
            if soak_seconds:
                operational_probes(receipt['operational'],soak_seconds,soak_concurrency,spawn,owners,run_id,
                    {'redis':redis_process,'backend':backend_process,'gateway':gateway},client,redis_run_id,redis_command,
                    backend_command,backend_env,env,gateway_env,gateway_port,context,signer,count_file)
            client.close()
        finally:
            if client is not None:
                client.close()
            settled=cleanup(processes)
            for handle in handles:
                handle.close()
            receipt['checks']['owned_process_cleanup']=settled
            receipt['owned_process_cleanup']=settled
            receipt['cleanup']=settled
            if soak_seconds:
                receipt['operational']['checks']['owned_process_cleanup']=settled
                receipt['operational']['passed']=receipt['operational']['passed'] and settled
                receipt['operational']['owned_children_started']=len(processes)
                receipt['operational']['owned_children_settled']=sum(process.poll() is not None for process in processes)
            try:
                require(bool(pins) and runtime is not None)
                verify_pins(pins,runtime,hashes)
                require(source_hashes()==source_pins)
                require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==receipt['candidate_commit'])
                receipt['source_matches_commit']=receipt['source_matches_commit'] and not bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT))
                receipt['provenance_unchanged']=True
                if soak_seconds:receipt['operational']['provenance_unchanged']=True
            except (AssertionError,OSError,ValueError,subprocess.SubprocessError):
                receipt['provenance_unchanged']=False
                if soak_seconds:
                    receipt['operational']['passed']=False
                    receipt['operational']['provenance_unchanged']=False
                receipt['checks']={name:False for name in CHECKS}
                receipt['checks']['owned_process_cleanup']=settled
            (output/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    require(all(receipt['checks'].values()))
    if soak_seconds:require(receipt['operational']['passed'] and all(receipt['operational']['checks'].values()))
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--maven',default=os.environ.get('APPGUARD_MAVEN','mvn'))
    parser.add_argument('--java-home',default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--redis-server',default=os.environ.get('APPGUARD_REDIS_SERVER','redis-server'))
    parser.add_argument('--soak-seconds',type=int,default=0,help='0 disables operational probes; otherwise 1..3600 seconds')
    parser.add_argument('--soak-concurrency',type=int,default=8,help='1..32 concurrent synthetic request workers')
    args=parser.parse_args()
    try:
        validate_soak_options(args.soak_seconds,args.soak_concurrency)
        require(args.java_home is not None)
        java=Path(args.java_home).resolve(strict=True)
        maven=Path(shutil.which(args.maven) or args.maven).resolve(strict=True)
        redis_server=Path(shutil.which(args.redis_server) or args.redis_server).resolve(strict=True)
        output=new_output(args.output)
        qualify(output,maven,java,redis_server,args.soak_seconds,args.soak_concurrency)
    except Exception:
        print('SPRING_QUALIFICATION_FAILED',file=sys.stderr)
        return 1
    print('SPRING_QUALIFICATION_PASSED')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
