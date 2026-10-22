#!/usr/bin/env python3
"""Actual local TLS/mTLS qualification. Never connects to an operator Redis URL.

Private ephemeral keys/logs stay in an owned temporary directory. The retained
receipt proves this local topology only, not a production deployment or audit.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
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
            .not_valid_after(now+timedelta(hours=1))
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


def qualify(output, maven, java_home, redis_server):
    import redis
    started=datetime.now(timezone.utc)
    receipt={'schema':1,'evidence_class':'local_deployment','profile':'spring-mtls-store-forward-v1',
        'candidate_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'observed_at':started.isoformat().replace('+00:00','Z'),
        'checks':{name:False for name in CHECKS},'release_ready':False,
        'limits':{'body_bytes':1048576,'upload_seconds':.8,'backend_seconds':2},
        'limitations':['local topology only','no external audit or provider validation','no physical device proof']}
    source_pins=source_hashes()
    receipt['source_sha256']={str(path.relative_to(ROOT)):value for path,value in source_pins.items()}
    receipt['source_matches_commit']=not bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT))
    pins={};runtime=None;hashes={}
    processes=[]
    with tempfile.TemporaryDirectory(prefix='appguard-spring-qualification-') as temporary:
        private=Path(temporary).resolve();private.chmod(0o700)
        handles=[]
        client=None
        def spawn(command, env, name):
            handle=(private/(name+'.log')).open('wb');os.chmod(handle.name,0o600);handles.append(handle)
            process=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=handle,stderr=subprocess.STDOUT)
            processes.append(process);return process
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
            redis_process=spawn([str(redis_server),'--bind','127.0.0.1','--port',str(redis_port),'--save','','--appendonly','no','--dir',str(private)],env,'redis')
            wait_port(redis_process,redis_port)
            client=redis.Redis(host='127.0.0.1',port=redis_port,socket_connect_timeout=1,socket_timeout=1)
            require(client.info('server')['process_id']==redis_process.pid)
            count_file=private/'counters.json';count_file.touch(mode=0o600)
            backend_env=env|{'APPGUARD_BACKEND_PORT':str(backend_port),'APPGUARD_BACKEND_KEYSTORE':str(private/'backend.p12'),
                'APPGUARD_BACKEND_KEYSTORE_PASSWORD':password,'APPGUARD_BACKEND_TRUSTSTORE':str(private/'trust.p12'),
                'APPGUARD_BACKEND_TRUSTSTORE_PASSWORD':password,'APPGUARD_APP_ID':'qualification-app',
                'APPGUARD_ORIGIN':'https://api.example.test','APPGUARD_SUBJECT':'qualification-user','APPGUARD_KEY_ID':'qualification-key',
                'APPGUARD_PUBLIC_KEY_FILE':str(private/'enrolled.pem'),'APPGUARD_BEARER_SHA256':hashlib.sha256(signer.token.encode()).hexdigest(),
                'APPGUARD_REDIS_URL':f'redis://127.0.0.1:{redis_port}/0','APPGUARD_BACKEND_COUNTER_FILE':str(count_file)}
            classpath=os.pathsep.join(map(str,[output/'backend.jar',*jars]))
            backend_process=spawn([str(java_home/'bin/java'),'-cp',classpath,'io.appguard.example.BackendMain'],backend_env,'backend')
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
            try:
                require(bool(pins) and runtime is not None)
                verify_pins(pins,runtime,hashes)
                require(source_hashes()==source_pins)
                require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==receipt['candidate_commit'])
                receipt['source_matches_commit']=receipt['source_matches_commit'] and not bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT))
                receipt['provenance_unchanged']=True
            except (AssertionError,OSError,ValueError,subprocess.SubprocessError):
                receipt['provenance_unchanged']=False
                receipt['checks']={name:False for name in CHECKS}
                receipt['checks']['owned_process_cleanup']=settled
            (output/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    require(all(receipt['checks'].values()))
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--maven',default=os.environ.get('APPGUARD_MAVEN','mvn'))
    parser.add_argument('--java-home',default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--redis-server',default=os.environ.get('APPGUARD_REDIS_SERVER','redis-server'))
    args=parser.parse_args()
    try:
        require(args.java_home is not None)
        java=Path(args.java_home).resolve(strict=True)
        maven=Path(shutil.which(args.maven) or args.maven).resolve(strict=True)
        redis_server=Path(shutil.which(args.redis_server) or args.redis_server).resolve(strict=True)
        output=new_output(args.output)
        qualify(output,maven,java,redis_server)
    except Exception:
        print('SPRING_QUALIFICATION_FAILED',file=sys.stderr)
        return 1
    print('SPRING_QUALIFICATION_PASSED')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
