"""#277-3: Engine._scope_audit must flag an out-of-scope host even when the PoC
URL hides it behind userinfo (`@`), a backslash, or an IPv6 literal. The old
regex truncated the authority, so the real connect host escaped the audit."""
import types
import unittest

from engine import Engine
from scope import Scope


def _audit(scope, request):
    stub = types.SimpleNamespace(scope=scope)
    return Engine._scope_audit(stub, {"request": request, "evidence": "", "hosts_contacted": []})


class ScopeAuditAuthority(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["inscope.example.com"])

    def test_userinfo_hides_real_host(self):
        self.assertTrue(_audit(self.scope, "GET https://inscope.example.com@evil.com/leak"))

    def test_backslash_authority(self):
        self.assertTrue(_audit(self.scope, "curl https://inscope.example.com\\@attacker.org/log"))

    def test_ipv6_literal_out_of_scope(self):
        self.assertTrue(_audit(self.scope, "http://[::1]:8080/admin"))

    def test_in_scope_not_flagged(self):
        self.assertEqual(_audit(self.scope, "GET https://inscope.example.com/ok"), [])


if __name__ == "__main__":
    unittest.main()
