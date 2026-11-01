import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from circuitlock import Policy, PolicyError, TransportError, safe_fetch
from circuitlock.cli import main as cli_main


class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=='/hi':
            self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
            self.wfile.write(b'hello circuitlock')
        elif self.path=='/redirect':
            self.send_response(302);self.send_header('Location','/hi');self.end_headers()
        elif self.path=='/redirect-external':
            self.send_response(302);self.send_header('Location','http://169.254.169.254/latest/meta-data/');self.end_headers()
        elif self.path=='/loop':
            self.send_response(302);self.send_header('Location','/loop');self.end_headers()
        elif self.path=='/large':
            self.send_response(200);self.send_header('Content-Length','500');self.end_headers()
            self.wfile.write(b'X'*500)
        elif self.path=='/chunked':
            self.send_response(200);self.end_headers();self.wfile.write(b'Y'*500)
        elif self.path=='/echo':
            self.send_response(200);self.end_headers();self.wfile.write((self.headers.get('Host') or '').encode())
        else:
            self.send_response(404);self.end_headers()
    def do_HEAD(self):
        self.send_response(200);self.send_header('Content-Length','0');self.end_headers()
    def log_message(self,*_):pass


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Server)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=cls.server.server_address[1]
        cls.policy=Policy(allowed_schemes=('http',),allowed_ports=(cls.port,),
                          allowed_cidrs=('127.0.0.0/8',),max_redirects=2)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=2)

    def url(self,path):return f'http://127.0.0.1:{self.port}{path}'

    def test_get_pinned_to_explicit_nonpublic_test_network(self):
        r=safe_fetch(self.url('/hi'),self.policy)
        self.assertEqual(r.status,200);self.assertEqual(r.content,b'hello circuitlock')
        self.assertEqual(r.size,17);self.assertEqual(len(r.sha256),64)

    def test_default_policy_blocks_local_test_server(self):
        with self.assertRaises(PolicyError):safe_fetch(self.url('/hi'))

    def test_head_does_not_read_body(self):
        r=safe_fetch(self.url('/hi'),self.policy,method='HEAD')
        self.assertEqual((r.status,r.size),(200,0))

    def test_disallow_post(self):
        with self.assertRaises(PolicyError):safe_fetch(self.url('/hi'),self.policy,method='POST')

    def test_relative_redirect_revalidates(self):
        r=safe_fetch(self.url('/redirect'),self.policy)
        self.assertEqual(r.status,200);self.assertEqual(r.redirects,1)

    def test_redirect_off_by_default(self):
        p=Policy(allowed_schemes=('http',),allowed_ports=(self.port,),allowed_cidrs=('127.0.0.0/8',))
        with self.assertRaises(TransportError):safe_fetch(self.url('/redirect'),p)

    def test_redirect_to_metadata_rejected(self):
        with self.assertRaises(PolicyError):safe_fetch(self.url('/redirect-external'),self.policy)

    def test_redirect_loop_rejected(self):
        with self.assertRaises(TransportError):safe_fetch(self.url('/loop'),self.policy)

    def test_content_length_precheck(self):
        p=Policy(allowed_schemes=('http',),allowed_ports=(self.port,),allowed_cidrs=('127.0.0.0/8',),max_response_bytes=20)
        with self.assertRaises(TransportError):safe_fetch(self.url('/large'),p)

    def test_unannounced_response_bound(self):
        p=Policy(allowed_schemes=('http',),allowed_ports=(self.port,),allowed_cidrs=('127.0.0.0/8',),max_response_bytes=20)
        with self.assertRaises(TransportError):safe_fetch(self.url('/chunked'),p)

    def test_explicit_host_header(self):
        r=safe_fetch(self.url('/echo'),self.policy)
        self.assertEqual(r.content.decode(),f'127.0.0.1:{self.port}')

    def test_http_404_is_returned_not_mislabeled_network_error(self):
        r=safe_fetch(self.url('/missing'),self.policy)
        self.assertEqual(r.status,404)

    def test_dns_only_once_and_numeric_socket_target(self):
        calls=[]
        def resolver(host,port):
            calls.append((host,port));return ['127.0.0.1']
        p=Policy(allowed_schemes=('http',),allowed_hosts=('example.com',),allowed_ports=(self.port,),
                 allowed_cidrs=('127.0.0.0/8',))
        r=safe_fetch(f'http://example.com:{self.port}/echo',p,resolver=resolver)
        self.assertEqual(r.content.decode(),f'example.com:{self.port}')
        self.assertEqual(calls,[('example.com',self.port)])

    def test_dns_rebind_mixed_blocks_before_request(self):
        p=Policy(allowed_schemes=('http',),allowed_hosts=('example.com',),allowed_ports=(self.port,))
        from circuitlock import ResolutionError
        with self.assertRaises(ResolutionError):
            safe_fetch(f'http://example.com:{self.port}/hi',p,resolver=lambda *_:['8.8.8.8','127.0.0.1'])

    def test_tls_hostname_preserved_by_socket_layer(self):
        from circuitlock.transport import _PinnedHTTPS
        from circuitlock.address import Destination
        conn=_PinnedHTTPS(Destination('https','example.com',443,'/','8.8.8.8',False),2)
        self.assertEqual(conn.host,'example.com')
        self.assertTrue(conn._context.check_hostname)
        self.assertEqual(conn._context.verify_mode, __import__('ssl').CERT_REQUIRED)

    def test_cli_writes_download_file_exclusively(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            pol=Path(d)/'policy.json'
            pol.write_text(json.dumps({'allowed_schemes':['http'],'allowed_ports':[self.port],
                                      'allowed_cidrs':['127.0.0.0/8']}))
            out=Path(d)/'body.bin'
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code=cli_main([self.url('/hi'),'--policy',str(pol),'--output',str(out)])
            self.assertEqual(code,0);self.assertEqual(out.read_bytes(),b'hello circuitlock')
            self.assertEqual(json.loads(output.getvalue())['written'],True)
            with contextlib.redirect_stderr(io.StringIO()),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main([self.url('/hi'),'--policy',str(pol),'--output',str(out)]),2)

    def test_cli_fail_closed_no_url_leak(self):
        url='https://attacker.example/secret?key=PRIVATE_NEVER_PRINT'
        with contextlib.redirect_stderr(io.StringIO()) as err,contextlib.redirect_stdout(io.StringIO()) as out:
            code=cli_main([url,'--policy','/does/not/exist.json'])
        self.assertEqual(code,2);self.assertEqual(out.getvalue(),'')
        self.assertNotIn('PRIVATE_NEVER_PRINT',err.getvalue())


if __name__=='__main__':unittest.main()
