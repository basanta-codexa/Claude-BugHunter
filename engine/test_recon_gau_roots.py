"""#276: _gau_urls must derive query roots from osint.enumeration_roots(scope),
not `".".join(host.split(".")[-2:])`, which truncates multi-label TLDs
(app.example.co.uk -> co.uk) and IP seeds (10.0.0.1 -> 0.1)."""
import types
import unittest
from unittest import mock

import recon


class GauRoots(unittest.TestCase):
    def _roots_for(self, in_scope, seeds):
        from scope import Scope
        scope = Scope(in_scope, seeds=seeds)
        calls = []

        def fake_run(args, **kw):
            calls.append(args[1])          # ["gau", <root>]
            return types.SimpleNamespace(stdout="")

        with mock.patch.object(recon, "which", return_value="/usr/bin/gau"), \
             mock.patch("subprocess.run", side_effect=fake_run):
            recon._gau_urls(scope, log=lambda *a: None)
        return calls

    def test_multi_label_tld_not_truncated(self):
        roots = self._roots_for(["*.example.co.uk"], ["https://app.example.co.uk/"])
        self.assertIn("example.co.uk", roots)
        self.assertNotIn("co.uk", roots)

    def test_ip_seed_not_truncated(self):
        roots = self._roots_for(["10.0.0.0/8"], ["http://10.0.0.1:8080/"])
        self.assertNotIn("0.1", roots)


if __name__ == "__main__":
    unittest.main()
