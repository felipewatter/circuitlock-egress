import json
import os
import tempfile
from pathlib import Path
import unittest

from circuitlock import Policy, PolicyError


class PolicyTests(unittest.TestCase):
    def test_default_is_https_only(self):
        p=Policy()
        self.assertEqual(p.allowed_schemes,('https',))
        self.assertEqual(p.allowed_ports,(443,))
        self.assertEqual(p.max_redirects,0)

    def test_valid_json_policy(self):
        policy=Policy.from_json(json.dumps({'allowed_hosts':['example.com'],'allowed_ports':[443],'max_redirects':2}))
        self.assertEqual(policy.allowed_hosts,('example.com',))
        self.assertEqual(policy.max_redirects,2)

    def test_policy_rejects_duplicate_keys(self):
        with self.assertRaises(PolicyError):Policy.from_json('{"max_redirects":0,"max_redirects":5}')

    def test_unknown_fields_rejected(self):
        with self.assertRaises(PolicyError):Policy.from_json('{"allow_all":true}')

    def test_policy_rejects_non_object(self):
        for val in ['[]','null','"text"','42','false']:
            with self.subTest(val=val),self.assertRaises(PolicyError):Policy.from_json(val)

    def test_policy_rejects_invalid_lists(self):
        for payload in [{'allowed_hosts':'example.com'},{'allowed_cidrs':'10.0.0.0/8'},{'allowed_ports':443}]:
            with self.subTest(payload=payload),self.assertRaises(PolicyError):Policy.from_json(json.dumps(payload))

    def test_policy_rejects_invalid_numeric_types(self):
        for field in ['max_redirects','max_response_bytes','timeout_seconds','max_dns_answers']:
            with self.subTest(field=field),self.assertRaises(PolicyError):Policy.from_json(json.dumps({field:True}))

    def test_policy_enforces_ranges(self):
        for payload in [{'max_redirects':6},{'max_response_bytes':0},{'timeout_seconds':31},{'max_dns_answers':33}]:
            with self.subTest(payload=payload),self.assertRaises(PolicyError):Policy.from_json(json.dumps(payload))

    def test_canonical_hostnames_required(self):
        for x in ['EXAMPLE.com','example.com.','*.example.com','host..example','-foo.example.com']:
            with self.subTest(x=x),self.assertRaises(PolicyError):Policy(allowed_hosts=(x,))

    def test_canonical_cidrs_required(self):
        for x in ['10.1.2.5/8','127.0.0.1','::1/abc','bad/24']:
            with self.subTest(x=x),self.assertRaises(PolicyError):Policy(allowed_cidrs=(x,))

    def test_private_allowlist_is_explicit(self):
        p=Policy(allowed_cidrs=('127.0.0.0/8',))
        self.assertEqual(str(p.networks[0]),'127.0.0.0/8')

    def test_duplicate_hosts_ports_networks(self):
        for kwargs in [{'allowed_hosts':('example.com','example.com')},{'allowed_ports':(443,443)},
                       {'allowed_cidrs':('127.0.0.0/8','127.0.0.0/8')}]:
            with self.subTest(kwargs=kwargs),self.assertRaises(PolicyError):Policy(**kwargs)

    def test_policy_size_limit(self):
        with self.assertRaises(PolicyError):Policy.from_json('{"x":"'+'A'*32768+'"}')

    def test_policy_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'policy.json';f.write_text('{"max_redirects":1}')
            self.assertEqual(Policy.from_file(f).max_redirects,1)
            symlink=Path(d)/'link.json'
            try:symlink.symlink_to(f)
            except OSError:return
            with self.assertRaises(PolicyError):Policy.from_file(symlink)

    def test_policy_invalid_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'p.json';f.write_text('{invalid')
            with self.assertRaises(PolicyError):Policy.from_file(f)


if __name__=='__main__':unittest.main()
