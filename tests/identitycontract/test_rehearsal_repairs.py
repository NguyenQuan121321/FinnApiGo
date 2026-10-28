"""PR27 regressions using synthetic transports only, never staging evidence."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import rehearsal as r
from test_rehearsal import claims, manifest


class RotationControl:
    """Based on the saved independent review control; model live session authority."""
    def __init__(self, phase, retain_old=False, accept_legacy=False):
        self.m = manifest()
        now = int(time.time())
        last = now - (1 if phase == "overlap" else 1000)
        self.m.update(last_old_issuance_unix=last, service_overlap_until_unix=last + 930)
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.old_key = base64.b64encode(bytes(range(32, 64))).decode()
        self.current = claims()
        self.token = r.signed(self.current, "new", self.key)
        self.old_token = r.signed(dict(self.current, iat=last, nbf=last, exp=last + 900), "old", self.old_key)
        self.legacy = r.signed({k: v for k, v in self.current.items() if k != "contract_ver"}, "new", self.key)
        self.env = {"F02_ACCESS_TOKEN": self.token, "F02_PREVIOUS_ACCESS_TOKEN": self.old_token,
                    "F02_LEGACY_ACCESS_TOKEN": self.legacy,
                    "F02_CURRENT_SIGNING_KEY": self.key, "F02_PREVIOUS_SIGNING_KEY": self.old_key,
                    "F02_CURRENT_SERVICE_KEY": "synthetic-current", "F02_PREVIOUS_SERVICE_KEY": "synthetic-old",
                    "F02_SYNTHETIC_EMAIL": "fixture@example.invalid", "F02_SYNTHETIC_PASSWORD": "password-canary"}
        self.phase, self.retain_old, self.accept_legacy = phase, retain_old, accept_legacy
        self.probe = r.Probe(self.m)
        self.consumer_tokens = []

    def transport(self, base, path, token=None, body=None, service=None):
        if path.endswith("/login") or path.endswith("/refresh-token"):
            return 200, {"data": {"accessToken": self.token, "refreshToken": "refresh-canary"}}
        if path.endswith("/logout"):
            return 200, None
        consumer = base == self.m["consumer_origin"]
        state = path.endswith("/introspect")
        if state:
            valid_ids = {self.m["service_kid"]}
            if self.phase == "overlap":
                valid_ids.add(self.m["previous_service_kid"])
            if service is None or service[0] not in valid_ids:
                return 401, None
            token = body["token"]
        if consumer:
            self.consumer_tokens.append(token)
            if token == self.legacy and self.accept_legacy:
                return 200, None
        keys = {"new": self.key}
        if self.phase == "overlap" or (consumer and self.retain_old):
            keys["old"] = self.old_key
        try:
            c = r.verify(token, keys, self.m["tenant"], "jakeai-service", int(time.time()))
        except (AssertionError, KeyError):
            c = json.loads(r.decode(token.split(".")[1]))
            if state and c.get("tid") not in (None, self.m["tenant"]):
                return 403, None
            return 401, None
        # Every valid token must match the live authoritative session/versions.
        if any(c[k] != self.current[k] for k in ("sid", "sub", "uid", "tid", "pwdver", "auth_epoch", "perms")):
            return 401, None
        if state:
            if body["tenant_id"] != c["tid"]:
                return 403, None
            return 200, {k: c[k] for k in ("contract_ver", "tid", "sub", "sid", "jti", "pwdver", "auth_epoch")} | {"active": True, "checked_at": int(time.time()), "max_cache_seconds": 15}
        return 200, None

    def run(self):
        with patch.dict(os.environ, self.env), patch.object(self.probe, "request", side_effect=self.transport):
            r.run(self.probe, self.phase)


class RehearsalRepairTests(unittest.TestCase):
    def test_rotation_challenges_reach_consumer_with_live_unexpired_control(self):
        for phase in ("overlap", "retired", "rollback"):
            with self.subTest(phase=phase):
                control = RotationControl(phase)
                control.run()
                cases = {c["case"]: c for c in control.probe.results}
                expected = 200 if phase == "overlap" else 401
                for label in ("captured-previous-access", "previous-signing-fresh-challenge"):
                    self.assertEqual(cases["consumer:" + label]["http_status"], expected)
                old_inputs = [t for t in control.consumer_tokens if json.loads(r.decode(t.split(".")[0])).get("kid") == "old"]
                fresh = old_inputs[-1]
                fresh_claims = json.loads(r.decode(fresh.split(".")[1]))
                self.assertTrue(r.signed(fresh_claims, "new", control.key) in control.consumer_tokens)
                # Direct permissive reference accepts the challenge: no expiry or
                # absent/foreign session can explain the strict consumer's denial.
                valid = r.verify(fresh, {"old": control.old_key}, control.m["tenant"], "jakeai-service", int(time.time()))
                self.assertGreater(valid["exp"], int(time.time()))
                self.assertEqual(valid["sid"], control.current["sid"])
                self.assertEqual(valid["exp"] - valid["iat"], 900)
                self.assertEqual(cases["consumer:current-signing-fresh-control"]["http_status"], 200)
                self.assertTrue(any(c["case"].startswith("consumer:") and c["http_status"] == 200 for c in control.probe.results))
                self.assertTrue(all(c["status"] == "PASS" for c in control.probe.results))

    def test_incorrect_consumer_retaining_retired_key_fails_actual_runner(self):
        for phase in ("retired", "rollback"):
            with self.subTest(phase=phase):
                control = RotationControl(phase, retain_old=True)
                with self.assertRaisesRegex(r.Blocked, "consumer:previous-signing-fresh-challenge"):
                    control.run()
                cases = {c["case"]: c for c in control.probe.results}
                self.assertEqual(cases["fixture:previous-signing-fresh-challenge"]["http_status"], 401)
                self.assertEqual(cases["consumer:previous-signing-fresh-challenge"]["status"], "FAIL")
                self.assertEqual(cases["consumer:previous-signing-fresh-challenge"]["http_status"], 200)

    def test_retirement_challenge_does_not_inherit_seed_token_expiry(self):
        control = RotationControl("retired")
        now = int(time.time())
        control.current.update(iat=now - 905, nbf=now - 905, exp=now - 5)
        control.token = r.signed(control.current, "new", control.key)
        control.env["F02_ACCESS_TOKEN"] = control.token
        # The seed is valid only within skew. The retirement challenge must be
        # independently unexpired, with a paired current-key success control.
        control.run()
        old_inputs = [t for t in control.consumer_tokens if json.loads(r.decode(t.split(".")[0])).get("kid") == "old"]
        fresh = r.verify(old_inputs[-1], {"old": control.old_key}, control.m["tenant"], "jakeai-service", int(time.time()))
        self.assertGreater(fresh["exp"], int(time.time()) + 890)
        self.assertTrue(r.signed(fresh, "new", control.key) in control.consumer_tokens)

    def test_consumer_legacy_rejection_and_incorrect_consumer_control(self):
        for phase in ("reauth", "rollback"):
            with self.subTest(phase=phase):
                strict = RotationControl(phase)
                strict.run()
                self.assertTrue(strict.legacy in strict.consumer_tokens)
                self.assertTrue(any(c["case"] == "consumer:legacy-reauth-required" and c["http_status"] == 401 for c in strict.probe.results))
                bad = RotationControl(phase, accept_legacy=True)
                with self.assertRaisesRegex(r.Blocked, "consumer:legacy-reauth-required"):
                    bad.run()

    def cleanup_path(self, refresh_payload, logout_status=200, introspection_failure=False, logout_error=False):
        control = RotationControl("reauth")
        probe, calls = control.probe, []
        replacement = r.signed(dict(control.current, jti="replacement-jti"), "new", control.key)
        if refresh_payload == "valid":
            refresh_payload = {"data": {"accessToken": replacement, "refreshToken": "replacement-refresh-canary"}}
        state_calls = 0

        def transport(base, path, token=None, body=None, service=None):
            nonlocal state_calls
            calls.append((path, token, body))
            if path.endswith("/refresh-token"):
                return 200, refresh_payload
            if path.endswith("/introspect"):
                state_calls += 1
                if introspection_failure and state_calls == 2:
                    return 503, None
            if path.endswith("/logout"):
                if logout_error:
                    raise OSError("transport-secret-canary")
                return logout_status, None
            return control.transport(base, path, token, body, service)

        error = None
        with patch.dict(os.environ, control.env), patch.object(probe, "request", side_effect=transport):
            try:
                r.login_rehearsal(probe, control.m["replicas"][0], control.key, "new", (control.m["service_kid"], "synthetic"), True)
            except Exception as caught:
                error = caught
        self.assertTrue(any(c[0].endswith("/refresh-token") for c in calls), "control must reach actual refresh path")
        return control, calls, error

    def test_malformed_refresh_preserves_cleanup_pair(self):
        payloads = (None, [], {}, {"data": None}, {"data": []}, {"data": {}},
                    {"data": {"accessToken": "untrusted-canary"}},
                    {"data": {"refreshToken": "untrusted-canary"}},
                    {"data": {"accessToken": "", "refreshToken": "untrusted-canary"}},
                    {"data": {"accessToken": 3, "refreshToken": "untrusted-canary"}})
        for payload in payloads:
            with self.subTest(shape=type(payload).__name__):
                control, calls, error = self.cleanup_path(payload)
                self.assertIsInstance(error, r.Blocked)
                logout = [c for c in calls if c[0].endswith("/logout")]
                self.assertEqual(len(logout), 1)
                self.assertTrue(logout[0][1] == control.token)
                self.assertTrue(logout[0][2]["refreshToken"] == "refresh-canary")
                cleanup = control.probe.results[-1]
                self.assertTrue(cleanup["logout_acknowledged"])
                self.assertTrue(cleanup["cleanup_unresolved"])
                self.assertEqual(cleanup["reason"], "refresh_outcome_unvalidated")
                self.assertNotIn("canary", json.dumps(control.probe.results))

    def test_refresh_verification_and_state_errors_keep_cleanup_credentials(self):
        invalid = {"data": {"accessToken": "invalid-token-canary", "refreshToken": "replacement-refresh-canary"}}
        for payload, state_error in ((invalid, False), ("valid", True)):
            with self.subTest(state_error=state_error):
                control, calls, error = self.cleanup_path(payload, introspection_failure=state_error)
                self.assertIsNotNone(error)
                logout = [c for c in calls if c[0].endswith("/logout")]
                self.assertEqual(len(logout), 1)
                self.assertTrue(logout[0][1] == control.token)
                self.assertTrue(control.probe.results[-1]["cleanup_unresolved"])
                self.assertNotIn("canary", json.dumps(control.probe.results))

    def test_cleanup_failure_preserves_original_and_reports_unresolved(self):
        for request_error in (False, True):
            with self.subTest(request_error=request_error):
                control, calls, error = self.cleanup_path({"data": {}}, logout_status=401, logout_error=request_error)
                self.assertIsInstance(error, r.Blocked)
                self.assertEqual(str(error), "invalid refresh token-pair response")
                self.assertEqual(sum(c[0].endswith("/logout") for c in calls), 1)
                cleanup = control.probe.results[-1]
                self.assertTrue(cleanup["cleanup_unresolved"])
                self.assertNotEqual(cleanup["status"], "PASS")
                self.assertNotIn("canary", json.dumps(control.probe.results))
                self.assertNotIn("canary", str(error))

    def test_validated_refresh_replaces_cleanup_and_cleanup_only_failure_blocks(self):
        for logout_status in (200, 401):
            with self.subTest(logout_status=logout_status):
                control, calls, error = self.cleanup_path("valid", logout_status=logout_status)
                logout = [c for c in calls if c[0].endswith("/logout")]
                self.assertEqual(len(logout), 1)
                self.assertTrue(logout[0][1] != control.token)
                self.assertTrue(logout[0][2]["refreshToken"] == "replacement-refresh-canary")
                self.assertEqual(error is None, logout_status == 200)
                self.assertEqual(control.probe.results[-1]["cleanup_unresolved"], logout_status != 200)

    def test_unavailable_login_credentials_record_unresolved_without_fake_logout(self):
        control = RotationControl("reauth")
        with patch.dict(os.environ, control.env), patch.object(control.probe, "request", return_value=(200, {"data": {}})) as request:
            with self.assertRaisesRegex(r.Blocked, "invalid login token-pair response"):
                r.login_rehearsal(control.probe, control.m["replicas"][0], control.key, "new", ("service", "synthetic"), True)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(control.probe.results[-1]["reason"], "cleanup_credentials_unavailable")
        self.assertTrue(control.probe.results[-1]["cleanup_unresolved"])

    def test_cli_preserves_refresh_failure_and_redacts_cleanup_transport_error(self):
        control = RotationControl("reauth")

        def transport(base, path, token=None, body=None, service=None):
            if path.endswith("/refresh-token"):
                return 200, {"data": {"accessToken": "replacement-access-canary"}}
            if path.endswith("/logout"):
                raise OSError("transport-error-secret-canary")
            return control.transport(base, path, token, body, service)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            raw = json.dumps(control.m).encode()
            path.write_bytes(raw)
            args = ["rehearsal", str(path), "--phase", "reauth", "--execute-reviewed-manifest-sha256", hashlib.sha256(raw).hexdigest()]
            with patch.dict(os.environ, control.env), patch.object(sys, "argv", args), patch.object(r.Probe, "request", side_effect=transport):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(r.main(), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "invalid refresh token-pair response")
        self.assertTrue(result["cases"][-1]["cleanup_unresolved"])
        self.assertEqual(result["cases"][-1]["reason"], "cleanup_request_failed")
        self.assertNotIn("canary", output.getvalue())
        self.assertNotIn(control.token, output.getvalue())

    def test_known_production_spellings_block_before_secrets_or_network(self):
        spellings = ("https://finnapigo.onrender.com", "https://FINNAPIGO.ONRENDER.COM",
                     "https://finnapigo.onrender.com.", "https://FINNAPIGO.ONRENDER.COM.:443/",
                     "https://finnapigo\u3002onrender\uff0ecom\uff61", "https://\uff46\uff49\uff4e\uff4e\uff41\uff50\uff49\uff47\uff4f.onrender.com")
        for endpoint in ("replica", "consumer"):
            for spelling in spellings:
                with self.subTest(endpoint=endpoint, spelling=spelling):
                    m = manifest()
                    if endpoint == "replica":
                        m["replicas"][0]["origin"] = spelling
                    else:
                        m["consumer_origin"] = spelling
                    probe = SimpleNamespace(m=m, request=unittest.mock.Mock())
                    with patch.object(r, "secret", side_effect=AssertionError("secret lookup")) as secret:
                        with self.assertRaises(r.Blocked):
                            r.run(probe, "overlap")
                    secret.assert_not_called()
                    probe.request.assert_not_called()

    def test_safe_dns_idna_and_unsupported_origin_controls(self):
        self.assertEqual(r.origin("https://Staging.Example.Invalid.:443/"), "https://staging.example.invalid")
        self.assertEqual(r.origin("https://b\u00fccher.example.invalid"), "https://xn--bcher-kva.example.invalid")
        for value in ("https://@example.invalid", "https://example.invalid?", "https://example.invalid#",
                      "https://example.invalid..", "https://bad_host.example.invalid", "https://example.invalid:bad",
                      "https://example.invalid\\evil", "https://example.invalid\n"):
            with self.subTest(value=value), self.assertRaises(r.Blocked):
                r.origin(value)
        m = manifest()
        m["consumer_origin"] = "https://Staging.Example.Invalid."
        self.assertIs(r.validate(m), m)


if __name__ == "__main__":
    unittest.main()
