"""#279: a malformed scope.json must fail closed, not weaken silently.

(1) A string where a list is expected (out_of_scope/in_scope/seeds) was iterated
one character at a time, so the deny list never matched and the excluded host
stayed in scope. (2) An engagement `name` with a path separator escaped --base.
"""
import os
import tempfile
import unittest

import scope as scope_mod
from scope import Scope
from state import Engagement


class ScopeTypeFailClosed(unittest.TestCase):
    def test_string_out_of_scope_raises(self):
        with self.assertRaises(ValueError):
            Scope(["*.example.com"], "admin.example.com")

    def test_string_in_scope_raises(self):
        with self.assertRaises(ValueError):
            Scope("example.com")

    def test_nonstring_member_raises(self):
        with self.assertRaises(ValueError):
            Scope(["ok.com", 123])

    def test_normal_lists_still_work(self):
        s = Scope(["*.example.com"], ["admin.example.com"])
        self.assertFalse(s.in_scope_host("admin.example.com"))
        self.assertTrue(s.in_scope_host("api.example.com"))


class EngagementNameFailClosed(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_traversal_name_rejected(self):
        for bad in ("../escaped", "a/b", "a\\b", "a:b", "", ".", ".."):
            with self.assertRaises(ValueError, msg=f"name {bad!r} not rejected"):
                Engagement(self._tmp(), bad)

    def test_none_name_rejected(self):
        with self.assertRaises(ValueError):
            Engagement(self._tmp(), None)

    def test_normal_name_ok(self):
        e = Engagement(self._tmp(), "demo-local")
        self.assertTrue(os.path.isdir(e.dir))


if __name__ == "__main__":
    unittest.main()
