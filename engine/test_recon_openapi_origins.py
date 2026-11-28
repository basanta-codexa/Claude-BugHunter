"""#278 (+#293): seed-origin handling and OpenAPI spec resilience in recon.

- platform_recon must keep a non-default seed port (#293), not probe 80/443.
- openapi_recon must probe the seed's ORIGIN, not append /openapi.json onto a
  path or query in the seed.
- OpenAPI parsing must survive valid Path Item metadata (x-* keys, summary,
  parameters, servers), null operations, null info/parameters, and $ref params
  with no "name", instead of raising.
"""
import json
import unittest
from unittest import mock

import recon
from scope import Scope


class PlatformReconPort(unittest.TestCase):
    def test_port_preserved(self):
        scope = Scope(["127.0.0.1/32"], seeds=["http://127.0.0.1:8443"])
        probed = []

        def fake_probe(url, allow=None):
            probed.append(url)
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nDisallow: /admin/\n"
            return 0, ""

        with mock.patch.object(recon, "_probe", side_effect=fake_probe):
            items = recon.platform_recon(scope, log=lambda *a: None)
        self.assertTrue(all(":8443" in u for u in probed), probed)
        self.assertTrue(any(it["url"] == "http://127.0.0.1:8443/admin/" for it in items))


class OpenapiOrigin(unittest.TestCase):
    def test_seed_with_path_normalizes_to_origin(self):
        scope = Scope(["api.example.com"], seeds=["https://api.example.com/v1/app?tab=1"])
        probed = []

        def fake_probe(url, allow=None):
            probed.append(url)
            return 0, ""

        with mock.patch.object(recon, "_probe", side_effect=fake_probe):
            recon.openapi_recon(scope, log=lambda *a: None)
        self.assertTrue(all(u.startswith("https://api.example.com/") and "v1/app" not in u for u in probed), probed)


class OpenapiMalformedSpec(unittest.TestCase):
    def test_metadata_and_nulls_do_not_crash(self):
        spec = {
            "info": None,
            "security": [{"x": []}],
            "paths": {
                "x-internal": {"note": "vendor ext"},
                "/good": {"summary": "s", "parameters": None,
                          "get": {"security": [{"x": []}], "parameters": [{"$ref": "#/c/p"}]},
                          "post": None},
            },
        }

        def fake_probe(url, allow=None):
            if url.endswith("/openapi.json"):
                return 200, json.dumps(spec)
            return 0, ""

        with mock.patch.object(recon, "_probe", side_effect=fake_probe), \
             mock.patch.object(recon, "auth_enforcement_sweep", return_value=[]):
            scope = Scope(["api.example.com"], seeds=["https://api.example.com"])
            items = recon.openapi_recon(scope, log=lambda *a: None)
        self.assertTrue(any(it["url"] == "https://api.example.com/good" for it in items))


if __name__ == "__main__":
    unittest.main()
