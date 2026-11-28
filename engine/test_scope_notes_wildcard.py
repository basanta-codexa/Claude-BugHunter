"""#277 + #298: more scope deny rules that fail open.

#277-1: a trailing parenthetical note on a non-CIDR rule (`admin.example.com
(internal portal)`) was kept in the host, so the deny rule matched nothing.
#277-2: an `@` in a rule's path/query (`.../@internal`, `?u=a@evil.org`) was
treated as userinfo, normalizing the deny rule to the wrong host.
#298: an out-of-scope rule with a `*` that is not a leading `*.`
(`staging-*.example.com`, `www.*.example.com`) matched nothing.
"""
import unittest

from scope import Scope


class RuleNoteFailClosed(unittest.TestCase):
    def test_parenthetical_note_on_host_deny(self):
        s = Scope(["*.example.com"], ["admin.example.com (internal portal)"])
        self.assertFalse(s.in_scope_host("admin.example.com"))

    def test_parenthetical_note_on_ip_deny(self):
        s = Scope(["10.0.0.0/8"], ["10.0.0.5 (bastion)"])
        self.assertFalse(s.in_scope_host("http://10.0.0.5/"))


class AtInPathFailClosed(unittest.TestCase):
    def test_at_in_path(self):
        s = Scope(["*.example.com"], ["https://admin.example.com/@internal"])
        self.assertFalse(s.in_scope_host("admin.example.com"))

    def test_at_in_query(self):
        s = Scope(["*.example.com"], ["https://staff.example.com?user=alice@evil.org"])
        self.assertFalse(s.in_scope_host("staff.example.com"))


class MidLabelOutWildcard(unittest.TestCase):
    def test_prefix_wildcard_excluded(self):
        s = Scope(["*.example.com"], ["staging-*.example.com"])
        self.assertFalse(s.in_scope_host("staging-7.example.com"))
        self.assertTrue(s.in_scope_host("app.example.com"))

    def test_mid_label_wildcard_excluded(self):
        s = Scope(["*.example.com"], ["www.*.example.com"])
        self.assertFalse(s.in_scope_host("www.eu.example.com"))


if __name__ == "__main__":
    unittest.main()
