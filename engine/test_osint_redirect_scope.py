"""#274: OSINT probing must not follow redirects off-scope, and seed probing /
crawling must skip out-of-scope seeds."""
import unittest
from unittest import mock

import osint
import recon
from scope import Scope


def _curl_reply(status, location=None, body=""):
    h = f"HTTP/1.1 {status} x\r\n"
    if location:
        h += f"Location: {location}\r\n"
    h += "Server: t\r\n\r\n"
    return h


class ProbeRedirect(unittest.TestCase):
    def test_no_dash_L_and_offscope_redirect_not_followed(self):
        allow = Scope(["in.example.com"]).in_scope_host
        calls = []

        def fake_run(cmd, timeout=0):
            calls.append(cmd)
            url = cmd[-1]
            # body file is written by curl; here just return headers
            if "in.example.com" in url and "evil" not in url:
                return _curl_reply(302, "https://evil.com/x")
            return _curl_reply(200)

        with mock.patch.object(osint, "_run", side_effect=fake_run):
            osint.probe("in.example.com", allow=allow)
        flat = [a for c in calls for a in c]
        self.assertNotIn("-L", flat, "curl must not auto-follow redirects")
        self.assertFalse(any("evil.com" in a for c in calls for a in c),
                         "off-scope redirect target must not be requested")


class ProbeHostsScope(unittest.TestCase):
    def test_offscope_hosts_filtered(self):
        scope = Scope(["in.example.com"])
        got = []
        with mock.patch.object(osint, "_pd_httpx", return_value=None), \
             mock.patch.object(osint, "probe", side_effect=lambda h, **k: got.append(h)):
            osint.probe_hosts(["in.example.com", "out.evil.com"], log=lambda *a: None, scope=scope)
        self.assertIn("in.example.com", got)
        self.assertNotIn("out.evil.com", got)


if __name__ == "__main__":
    unittest.main()
