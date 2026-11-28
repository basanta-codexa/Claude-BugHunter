"""verifier._redact must strip AWS SecretAccessKey + session Token from a stored
response body, not only the AccessKeyId (privately reported gap).

Evidence redaction errs toward over-redaction: a false positive hides a benign
value in a local excerpt (harmless), a false negative writes a live secret to
the state file (the bug). But it must NOT eat the deterministic oracle signals
(root:x:, SQL errors, reflected canaries) — those are not key:value shaped.
"""
import unittest

import verifier


class RedactionTests(unittest.TestCase):
    AWS = ('{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
           '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
           '"SessionToken":"FQoGZXIvYXdzEMaDExampleSessionTokenValue0123456789abcdef",'
           '"Token":"IQoJb3JpZ2luX2VjExampleTokenValue0123456789abcdefghij"}')

    def test_aws_credentials_fully_redacted(self):
        red = verifier._redact(self.AWS)
        for secret in ("AKIAIOSFODNN7EXAMPLE",
                       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                       "FQoGZXIvYXdzEMaDExampleSessionTokenValue0123456789abcdef",
                       "IQoJb3JpZ2luX2VjExampleTokenValue0123456789abcdefghij"):
            self.assertNotIn(secret, red, f"leaked: {secret}")

    def test_form_encoded_secret_redacted(self):
        red = verifier._redact("client_secret=s3cr3tVALUE123456&grid=on&refresh_token=rt_ABCDEF123456")
        self.assertNotIn("s3cr3tVALUE123456", red)
        self.assertNotIn("rt_ABCDEF123456", red)

    def test_does_not_over_redact_oracle_signals(self):
        # the corroborator's fact signals must survive redaction untouched
        self.assertIn("root:x:0:0:", verifier._redact("root:x:0:0:root:/root:/bin/bash"))
        self.assertIn("SQL syntax", verifier._redact("You have an error in your SQL syntax near ''"))
        self.assertIn("<script>cbh1</script>", verifier._redact("echo <script>cbh1</script> done"))

    def test_no_double_redaction_artifact(self):
        # a token matched by both the key rule and the prefix rule must redact once
        red = verifier._redact('{"Token":"FQoGZXIvYXdzEMaDExampleToken0123456789abcdefghij"}')
        self.assertNotIn("[REDACTED-SECRET]]", red)
        self.assertEqual(red.count("[REDACTED-SECRET]"), 1)

    def test_benign_token_count_field_not_a_false_positive_on_the_key(self):
        # a field whose NAME merely contains 'token' as a sub-substring is not a secret key
        red = verifier._redact('{"user_token_count": 5, "is_secretive": false}')
        self.assertIn("5", red)
        self.assertIn("false", red)


if __name__ == "__main__":
    unittest.main()


class LocationFieldRedaction(unittest.TestCase):
    def test_capture_exchange_redacts_location_field_without_breaking_open_redirect(self):
        import verifier
        loc = "https://app.example.com/cb?access_token=AKIAIOSFODNN7EXAMPLE&email=a@b.com"
        fetch = lambda url: (302, {"Location": loc}, loc, "")
        scope = type("S", (), {"reject_reason": lambda self, u: None})()
        ex = verifier.capture_exchange({"url": "https://app.example.com/go", "request": "GET /go"},
                                       fetch, scope)["exchange"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", ex["location"])
        self.assertNotIn("a@b.com", ex["location"])
        self.assertIn("app.example.com", ex["location"])   # host kept for open-redirect check

    def test_none_location_preserved(self):
        import verifier
        fetch = lambda url: (200, {}, None, "ok")
        scope = type("S", (), {"reject_reason": lambda self, u: None})()
        ex = verifier.capture_exchange({"url": "https://x.example.com/", "request": "GET /"},
                                       fetch, scope)["exchange"]
        self.assertIsNone(ex["location"])
