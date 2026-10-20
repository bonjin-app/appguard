"""Loopback raw HTTP integration against a PHP ingress harness; no framework claim."""
import json, os, pathlib, socket, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
php=sys.argv[1]
v=json.loads((root.parents[1]/'conformance/v0/http.json').read_text())[0]
proc=subprocess.Popen([php,'-n',str(root/'tests/http_server.php')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 host,port=proc.stdout.readline().strip().split(':');port=int(port)
 def call(target='/v1/items?b=2&a=1',extra=(),body=b'{}'):
  headers=v['headers']+[['Host','api.example.test'],['Content-Length',str(len(body))]]+list(extra)
  raw=('POST '+target+' HTTP/1.1\r\n'+''.join(k+': '+value+'\r\n' for k,value in headers)+'\r\n').encode()+body
  with socket.create_connection((host,port),timeout=5) as sock:
   sock.sendall(raw); chunks=[]
   while True:
    chunk=sock.recv(65536)
    if not chunk:break
    chunks.append(chunk)
  head,out=b''.join(chunks).split(b'\r\n\r\n',1)
  return int(head.split(b' ')[1]),json.loads(out)
 status,data=call();assert status==200 and data=={'body_b64':'e30=','existing':'preserved','verified':'VERIFIED'},(status,data)
 assert call()==(403,{'code':'REPLAY_DETECTED'})
 assert call(extra=[['AUTHORIZATION','Bearer OTHER']])==(400,{'code':'INVALID_REQUEST'})
 assert call('/missing-evidence')==(400,{'code':'INVALID_REQUEST'})
 assert call(body=b'{"changed":true}')==(403,{'code':'DIGEST_MISMATCH'})
 assert proc.wait(timeout=10)==0,proc.stderr.read()
 print('PASS: 5 loopback raw HTTP adapter requests (body/identity, replay, duplicates, missing evidence, tamper)')
finally:
 if proc.poll() is None:proc.kill();proc.wait()
 err=proc.stderr.read()
 if err:sys.stderr.write(err)
