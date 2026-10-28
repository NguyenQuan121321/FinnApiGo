"""Offline orchestration/safety tests; never staging or Jake runtime evidence."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import rehearsal as r


def manifest():
    now = int(time.time())
    return {
        "environment": "isolated-synthetic-staging",
        **{k: "offline-fixture" for k in ("identity_owner", "security_owner", "platform_owner", "risk_disposition_ref",
           "mysql_resource_ref", "redis_resource_ref", "tls_trust_ref", "rollback_ref", "authorization_ref", "consumer_decision_ref")},
        "finn_sha": "a" * 40, "jake_sha": "b" * 40,
        "replicas": [{"id": "fixture", "origin": "https://issuer.example.invalid", "deployment_ref": "offline-only"}],
        "consumer_kind": "dedicated-contract-probe", "consumer_origin": "https://consumer.example.invalid", "consumer_path": "/protected",
        "tenant": "synthetic-a", "foreign_tenant": "synthetic-b", "current_kid": "new", "previous_kid": "old",
        "service_kid": "new-service", "previous_service_kid": "old-service",
        "last_old_issuance_unix": now - 1, "service_overlap_until_unix": now + 900,
    }


def claims():
    now = int(time.time())
    return {"contract_ver": 1, "iss": "finnapigo", "aud": ["finnapigo-api", "jakeai-service"], "type": "access",
            "uid": 1, "sub": "1", "tid": "synthetic-a", "sid": "fixture-session", "jti": "fixture-jti",
            "pwdver": 0, "auth_epoch": 0, "perms": ["chat:read"], "iat": now, "nbf": now, "exp": now + 900}


class RehearsalTests(unittest.TestCase):
    def test_plan_never_reads_secrets_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(manifest()), encoding="utf-8")
            with patch.object(sys, "argv", ["rehearsal", str(path)]), patch.object(r, "Probe", side_effect=AssertionError("network")), patch.object(r, "secret", side_effect=AssertionError("secret")):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(r.main(), 0)
                self.assertEqual(json.loads(output.getvalue())["status"], "NOT_RUN")

    def test_unreviewed_manifest_and_optimized_python_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(manifest()), encoding="utf-8")
            for options in (["--execute-reviewed-manifest-sha256", "wrong"], []):
                command = [sys.executable, "-B"]
                if not options:
                    command.append("-O")
                command += [str(Path(r.__file__).resolve()), str(path)] + options
                completed = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(json.loads(completed.stdout)["status"], "BLOCKED")

    def test_origin_boundary(self):
        for value in ("http://issuer.example.invalid", "https://finnapigo.onrender.com", "https://name:password@example.invalid", "https://example.invalid/?token=x", "https://example.invalid/#x"):
            with self.subTest(value=value), self.assertRaises(r.Blocked):
                r.origin(value)
        with self.assertRaises(r.Blocked):
            r.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example.invalid")

    def test_missing_owners_and_clock_window_block_before_requests(self):
        m = manifest()
        m["security_owner"] = ""
        with self.assertRaises(r.Blocked):
            r.validate(m)
        m = manifest()
        m["service_overlap_until_unix"] = m["last_old_issuance_unix"] + 931
        with self.assertRaises(r.Blocked):
            r.validate(m)
        probe = r.Probe(manifest())
        with patch.object(probe, "request", side_effect=AssertionError("network")):
            with self.assertRaises(r.Blocked):
                r.run(probe, "retired")

    def test_signed_negative_corpus_fails_reference(self):
        key = base64.b64encode(bytes(range(32))).decode()
        valid = claims()
        self.assertEqual(r.verify(r.signed(valid, "new", key), {"new": key}, valid["tid"], "jakeai-service", int(time.time()))["sub"], "1")
        cases = list(r.negatives(valid, "new", key))
        self.assertEqual(len(cases), 20)
        for name, token in cases:
            with self.subTest(name=name), self.assertRaises((AssertionError, KeyError)):
                r.verify(token, {"new": key}, valid["tid"], "jakeai-service", int(time.time()))

    def test_success_status_cannot_hide_bad_authority_response(self):
        key = base64.b64encode(bytes(range(32))).decode()
        token = r.signed(claims(), "new", key)
        for payload in ({"active": True}, {"active": False}, None):
            probe = r.Probe(manifest())
            with patch.object(probe, "request", return_value=(200, payload)), self.assertRaises(r.Blocked):
                probe.introspect(probe.m["replicas"][0], token, ("service", "secret-canary"))
            self.assertNotIn("secret-canary", json.dumps(probe.results))
            self.assertEqual(probe.results[0]["status"], "FAIL")

    def test_real_dto_shape_and_cleanup_after_issuer_key_failure(self):
        key = base64.b64encode(bytes(range(32))).decode()
        token = r.signed(claims(), "unexpected-old", key)
        probe = r.Probe(manifest())
        responses = [(200, {"data": {"accessToken": token, "refreshToken": "synthetic-refresh-canary"}}), (200, None)]
        with patch.dict(os.environ, {"F02_SYNTHETIC_EMAIL": "fixture@example.invalid", "F02_SYNTHETIC_PASSWORD": "synthetic-password-canary"}), patch.object(probe, "request", side_effect=responses) as request:
            with self.assertRaises(AssertionError):
                r.login_rehearsal(probe, probe.m["replicas"][0], key, "new", ("service", "secret"), False)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.args[1], "/api/v1/auth/logout")
        self.assertNotIn("canary", json.dumps(probe.results))

    def test_overlap_orchestrates_live_controls_and_negative_matrix(self):
        # Transport is deliberately simulated. This verifies orchestration only.
        m = manifest()
        key = base64.b64encode(bytes(range(32))).decode()
        old_key = base64.b64encode(bytes(range(32, 64))).decode()
        current = claims()
        old = dict(current, iat=m["last_old_issuance_unix"], nbf=m["last_old_issuance_unix"], exp=m["last_old_issuance_unix"] + 900)
        token = r.signed(current, "new", key)
        old_token = r.signed(old, "old", old_key)
        environment = {"F02_ACCESS_TOKEN": token, "F02_PREVIOUS_ACCESS_TOKEN": old_token,
                       "F02_CURRENT_SIGNING_KEY": key, "F02_PREVIOUS_SIGNING_KEY": old_key,
                       "F02_CURRENT_SERVICE_KEY": "service-canary", "F02_PREVIOUS_SERVICE_KEY": "old-service-canary",
                       "F02_SYNTHETIC_EMAIL": "fixture@example.invalid", "F02_SYNTHETIC_PASSWORD": "password-canary"}
        probe = r.Probe(m)

        def transport(base, path, token=None, body=None, service=None):
            if path.endswith("/login"):
                return 200, {"data": {"accessToken": environment["F02_ACCESS_TOKEN"], "refreshToken": "refresh-canary"}}
            if path.endswith("/logout"):
                return 200, None
            if path.endswith("/introspect"):
                if service is None or service[0] == "wrong":
                    return 401, None
                token = body["token"]
            try:
                c = r.verify(token, {"new": key, "old": old_key}, m["tenant"], "jakeai-service", int(time.time()))
            except (AssertionError, KeyError):
                c = json.loads(r.decode(token.split(".")[1]))
                if path.endswith("/introspect") and c.get("tid") not in (None, m["tenant"]):
                    return 403, None
                return 401, None
            if path.endswith("/introspect"):
                if body["tenant_id"] != c["tid"]:
                    return 403, None
                return 200, {k: c[k] for k in ("contract_ver", "tid", "sub", "sid", "jti", "pwdver", "auth_epoch")} | {"active": True, "checked_at": int(time.time()), "max_cache_seconds": 15}
            return 200, None

        with patch.dict(os.environ, environment), patch.object(probe, "request", side_effect=transport):
            r.run(probe, "overlap")
        cases = {case["case"] for case in probe.results}
        self.assertIn("fixture:actual-issuer-key-and-state", cases)
        self.assertIn("fixture:captured-previous-access", cases)
        self.assertIn("fixture:previous-signing-fresh-challenge", cases)
        self.assertIn("fixture:previous-service", cases)
        self.assertIn("consumer:missing-algorithm", cases)
        self.assertTrue(all(case["status"] == "PASS" for case in probe.results))
        self.assertNotIn("canary", json.dumps(probe.results))


if __name__ == "__main__":
    unittest.main()
