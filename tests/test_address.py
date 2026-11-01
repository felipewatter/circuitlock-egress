import unittest
from ipaddress import ip_address
from circuitlock import Policy, PolicyError, ResolutionError, resolve_destination


class AddressTests(unittest.TestCase):
    def test_public_resolver(self):
        d = resolve_destination('https://example.com/path?a=1', resolver=lambda h,p:['8.8.8.8'])
        self.assertEqual((d.hostname, d.port, d.target, d.ip), ('example.com',443,'/path?a=1','8.8.8.8'))

    def test_hostname_case_and_dot_normalized(self):
        d=resolve_destination('https://EXAMPLE.com./x',resolver=lambda *_:['1.1.1.1'])
        self.assertEqual(d.hostname,'example.com')

    def test_ipv6_public_literal(self):
        d=resolve_destination('https://[2606:4700:4700::1111]/',resolver=lambda *_:self.fail('must not resolve'))
        self.assertEqual(d.ip,'2606:4700:4700::1111')

    def test_default_denies_insecure_http(self):
        with self.assertRaises(PolicyError):resolve_destination('http://example.com',resolver=lambda *_:['8.8.8.8'])

    def test_default_denies_unusual_ports(self):
        with self.assertRaises(PolicyError):resolve_destination('https://example.com:444',resolver=lambda *_:['8.8.8.8'])

    def test_default_denies_ip_loopback(self):
        for host in ['127.0.0.1','0.0.0.0','10.0.0.1','192.168.1.2','169.254.169.254','100.64.0.1','172.16.0.2']:
            with self.subTest(host=host), self.assertRaises(ResolutionError):resolve_destination(f'https://{host}')

    def test_default_denies_ipv6_specials(self):
        for host in ['::1','fe80::1','fc00::1','::ffff:8.8.8.8','2002:0a00:0001::1','2001:0:1234::1']:
            with self.subTest(host=host), self.assertRaises(ResolutionError):resolve_destination(f'https://[{host}]')

    def test_resolves_all_dns_records_and_denies_mixed_answers(self):
        for addresses in [['8.8.8.8','127.0.0.1'],['2606:4700:4700::1111','::1'],['8.8.8.8','169.254.169.254']]:
            with self.subTest(addresses=addresses), self.assertRaises(ResolutionError):
                resolve_destination('https://example.com',resolver=lambda *_:addresses)

    def test_empty_and_oversized_dns(self):
        for answers in [[],['8.8.8.8']*33,'not-a-list']:
            with self.subTest(answers=answers), self.assertRaises(ResolutionError):
                resolve_destination('https://example.com',resolver=lambda *_:answers)

    def test_bad_dns_value(self):
        with self.assertRaises(ResolutionError):resolve_destination('https://example.com',resolver=lambda *_:['bad-ip'])

    def test_dns_resolution_failure(self):
        def fail(*_):raise OSError('private.registry.credentials@domain')
        with self.assertRaisesRegex(ResolutionError,'DNS resolution failed'):
            resolve_destination('https://example.com',resolver=fail)

    def test_port_allowlist(self):
        policy=Policy(allowed_ports=(443,8443))
        d=resolve_destination('https://example.com:8443',policy,resolver=lambda *_:['1.1.1.1'])
        self.assertEqual(d.port,8443)

    def test_hostname_allowlist_exact(self):
        policy=Policy(allowed_hosts=('example.com',))
        self.assertEqual(resolve_destination('https://example.com',policy,resolver=lambda *_:['8.8.8.8']).hostname,'example.com')
        with self.assertRaises(PolicyError):resolve_destination('https://sub.example.com',policy,resolver=lambda *_:['8.8.8.8'])

    def test_nonpublic_explicit_override(self):
        policy=Policy(allowed_cidrs=('127.0.0.0/8',))
        self.assertEqual(resolve_destination('https://127.0.0.1',policy).ip,'127.0.0.1')
        with self.assertRaises(ResolutionError):resolve_destination('https://10.10.10.10',policy)

    def test_cross_family_override_does_not_bypass_mapped(self):
        policy=Policy(allowed_cidrs=('::/0','0.0.0.0/0'))
        with self.assertRaises(ResolutionError):resolve_destination('https://[::ffff:8.8.8.8]',policy)

    def test_host_disallow_special_names(self):
        for host in ['localhost','metadata.google.internal','x.local','company.home.arpa','example.internal','metadata']:
            with self.subTest(host=host),self.assertRaises(PolicyError):
                resolve_destination('https://'+host,resolver=lambda *_:['8.8.8.8'])

    def test_forbidden_url_schemes(self):
        for u in ['file:///etc/passwd','ftp://example.com/x','gopher://example.com','data:text/plain,secret','javascript:alert(1)']:
            with self.subTest(u=u),self.assertRaises(PolicyError):resolve_destination(u)

    def test_credentials_rejected(self):
        for u in ['https://user:pass@example.com','https://user@example.com','https://example.com@evil.com']:
            with self.subTest(u=u),self.assertRaises(PolicyError):resolve_destination(u)

    def test_control_characters_rejected(self):
        for u in ['https://example.com/\r\nX:evil',' https://example.com','https://example.com\t','https://example.com/a b','https://example.com\\@evil']:
            with self.subTest(u=u),self.assertRaises(PolicyError):resolve_destination(u)

    def test_fragments_rejected(self):
        with self.assertRaises(PolicyError):resolve_destination('https://example.com/#fragment')

    def test_hostname_unicode_and_encoded_rejected(self):
        for url in ['https://exämple.com','https://%31%32%37.0.0.1','https://example.com%00.local']:
            with self.subTest(url=url),self.assertRaises(PolicyError):resolve_destination(url)

    def test_urls_with_bad_port_rejected(self):
        for url in ['https://example.com:abc','https://example.com:65536','https://example.com:0']:
            with self.subTest(url=url),self.assertRaises(PolicyError):resolve_destination(url)

    def test_oversized_url(self):
        with self.assertRaises(PolicyError):resolve_destination('https://example.com/'+'a'*8192)

    def test_deterministic_address_selection(self):
        d=resolve_destination('https://example.com',resolver=lambda *_:['8.8.4.4','8.8.8.8','8.8.8.8'])
        self.assertEqual(d.ip,'8.8.4.4')


if __name__=='__main__':unittest.main()
