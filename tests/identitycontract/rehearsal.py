"""F02 synthetic staging probes. Plan mode is offline; never deploys or rotates keys.

Execution requires separately granted target-specific authority and the SHA256 of
the reviewed manifest. Neither the flag nor a successful probe grants acceptance.
"""
import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from verifier import decode, verify


PHASES = ("baseline", "overlap", "retired", "mysql-outage", "redis-outage", "reauth", "rollback")


class Blocked(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("redirect refused; credentials must remain on reviewed origin")


def origin(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value) or any(c in value for c in "\\?#"):
        raise Blocked("exact HTTPS origin required")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().removesuffix(".")
        port = parsed.port
    except (ValueError, UnicodeError):
        raise Blocked("unsupported HTTPS origin spelling") from None
    if (parsed.scheme != "https" or not host or parsed.username is not None or
            parsed.password is not None or parsed.path not in ("", "/") or
            parsed.netloc.endswith(":") or port == 0):
        raise Blocked("exact HTTPS origin required")
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise Blocked("supported DNS hostname required")
    if host == "finnapigo.onrender.com":
        raise Blocked("known production origin is forbidden")
    return "https://" + host + (":" + str(port) if port not in (None, 443) else "")


def secret(name):
    if not isinstance(name, str) or not re.fullmatch(r"F02_[A-Z0-9_]+", name):
        raise Blocked("dedicated F02 environment reference required")
    value = os.environ.get(name)
    if not value:
        raise Blocked("required secret reference is not injected: " + name)
    return value


def validate(manifest):
    if manifest.get("environment") != "isolated-synthetic-staging":
        raise Blocked("isolated synthetic staging attestation required")
    for field in ("identity_owner", "security_owner", "platform_owner", "risk_disposition_ref",
                  "mysql_resource_ref", "redis_resource_ref", "tls_trust_ref", "rollback_ref",
                  "authorization_ref", "consumer_decision_ref"):
        if not manifest.get(field):
            raise Blocked("missing non-secret input: " + field)
    for field in ("finn_sha", "jake_sha"):
        if not re.fullmatch(r"[0-9a-f]{40}", manifest.get(field, "")):
            raise Blocked("exact revision required: " + field)
    replicas = manifest.get("replicas", [])
    if not replicas or len({r["id"] for r in replicas}) != len(replicas):
        raise Blocked("unique replica inventory required")
    for replica in replicas:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", replica["id"]):
            raise Blocked("safe replica identity required")
        origin(replica["origin"])
        if not replica.get("deployment_ref"):
            raise Blocked("completed deployment evidence required for each replica")
    if manifest.get("consumer_kind") not in ("jake-runtime", "dedicated-contract-probe"):
        raise Blocked("identify consumer policy boundary")
    if manifest.get("consumer_origin"):
        origin(manifest["consumer_origin"])
        path = manifest.get("consumer_path", "")
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise Blocked("exact protected consumer GET path required")
    else:
        raise Blocked("consumer origin/path unavailable")
    if not manifest.get("tenant") or not manifest.get("foreign_tenant") or manifest["tenant"] == manifest["foreign_tenant"]:
        raise Blocked("two distinct synthetic tenants required")
    for field in ("current_kid", "previous_kid", "service_kid", "previous_service_kid"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", manifest.get(field, "")):
            raise Blocked("explicit key identity required: " + field)
    if manifest["current_kid"] == manifest["previous_kid"] or manifest["service_kid"] == manifest["previous_service_kid"]:
        raise Blocked("rotation requires distinct key identities")
    last, until = manifest.get("last_old_issuance_unix"), manifest.get("service_overlap_until_unix")
    if type(last) is not int or type(until) is not int or not last <= until <= last + 930:
        raise Blocked("real last issuance and service deadline within one 930-second window required")
    return manifest


class Probe:
    def __init__(self, manifest):
        self.m = validate(manifest)
        # Explicit trust store or OS defaults. No certificate-validation bypass.
        context = ssl.create_default_context(cafile=os.environ.get("F02_CA_FILE") or None)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                               urllib.request.HTTPSHandler(context=context), NoRedirect())
        self.results = []

    def request(self, base, path, token=None, body=None, service=None):
        headers = {"Content-Type": "application/json", "X-Tenant-ID": self.m["tenant"]}
        if token:
            headers["Authorization"] = "Bearer " + token
        if service:
            headers["Authorization"] = "Bearer " + service[1]
            headers["X-Service-Key-ID"] = service[0]
        request = urllib.request.Request(origin(base) + path, headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
        try:
            response = self.http.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise Blocked("response exceeds probe bound")
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError):
                payload = None
            return response.code, payload

    def check(self, name, status, expected, condition=True):
        passed = status == expected and condition
        self.results.append({"case": name, "status": "PASS" if passed else "FAIL",
                             "http_status": status, "expected": expected, "observed_unix": int(time.time())})
        if not passed:
            raise Blocked("probe failed: " + name)

    def introspect(self, replica, token, service, expected=200, tenant=None, label="state"):
        status, data = self.request(replica["origin"], "/api/v1/identity/introspect",
                                    body={"token": token, "tenant_id": tenant or self.m["tenant"]}, service=service)
        valid = True
        if expected == 200:
            c = json.loads(decode(token.split(".")[1]))
            valid = isinstance(data, dict) and set(data) == {"contract_ver", "active", "tid", "sub", "sid", "jti", "pwdver", "auth_epoch", "checked_at", "max_cache_seconds"}
            valid = valid and data["active"] is True and data["contract_ver"] == 1
            valid = valid and all(data[k] == c[k] for k in ("tid", "sub", "sid", "jti", "pwdver", "auth_epoch"))
            valid = valid and type(data["checked_at"]) is int and abs(time.time() - data["checked_at"]) <= 30
            valid = valid and type(data["max_cache_seconds"]) is int and 0 <= data["max_cache_seconds"] <= 15
        self.check(replica["id"] + ":" + label, status, expected, valid)

    def consumer(self, token, expected, label):
        status, _ = self.request(self.m["consumer_origin"], self.m["consumer_path"], token=token)
        self.check("consumer:" + label, status, expected)


def signed(claims, kid, key, algorithm="HS256"):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    header = {k: v for k, v in {"alg": algorithm, "kid": kid}.items() if v is not None}
    message = encode(header) + "." + encode(claims)
    digest = hashlib.sha512 if algorithm == "HS512" else hashlib.sha256
    signature = hmac.new(base64.b64decode(key, validate=True), message.encode(), digest).digest()
    return message + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def negatives(claims, kid, key):
    for field, wrong in (("type", "reset"), ("aud", ["finnapigo-api"]), ("iss", "other"),
                         ("sub", "0"), ("tid", "foreign-synthetic"), ("exp", claims["iat"] + 901),
                         ("iat", int(time.time()) + 60)):
        changed = copy.deepcopy(claims)
        changed[field] = wrong
        yield "wrong-" + field, signed(changed, kid, key)
    for field in ("type", "aud", "iss", "tid", "uid", "sub", "pwdver", "perms", "contract_ver"):
        changed = copy.deepcopy(claims)
        del changed[field]
        yield "missing-" + field, signed(changed, kid, key)
    yield "unknown-kid", signed(claims, "unconfigured-synthetic-kid", key)
    yield "missing-kid", signed(claims, None, key)
    yield "wrong-algorithm", signed(claims, kid, key, "HS512")
    yield "missing-algorithm", signed(claims, kid, key, None)


def token_pair(payload, operation):
    pair = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(pair, dict) or not all(isinstance(pair.get(k), str) and pair[k].strip() for k in ("accessToken", "refreshToken")):
        raise Blocked("invalid " + operation + " token-pair response")
    return {k: pair[k] for k in ("accessToken", "refreshToken")}


def cleanup_session(probe, replica, pair, refresh_unvalidated=False):
    """One bounded attempt, no secret/error text and no implied revocation."""
    result = {"case": replica["id"] + ":synthetic-session-cleanup", "status": "BLOCKED",
              "http_status": None, "expected": 200, "observed_unix": int(time.time()),
              "cleanup_unresolved": True}
    if pair is None:
        result["reason"] = "cleanup_credentials_unavailable"
    else:
        try:
            status, _ = probe.request(replica["origin"], "/api/v1/auth/logout", token=pair["accessToken"], body={"refreshToken": pair["refreshToken"]})
            result.update(http_status=status, status="PASS" if status == 200 else "FAIL", cleanup_unresolved=status != 200, logout_acknowledged=status == 200)
            if status != 200:
                result["reason"] = "cleanup_not_acknowledged"
            elif refresh_unvalidated:
                # The fallback logout receipt cannot establish the fate of an
                # unknown/unvalidated replacement created by refresh rotation.
                result.update(status="BLOCKED", cleanup_unresolved=True, reason="refresh_outcome_unvalidated")
        except Exception:  # Best effort must not replace the original failure.
            result["reason"] = "cleanup_request_failed"
    probe.results.append(result)
    return not result["cleanup_unresolved"]


def login_rehearsal(probe, replica, signing, kid, service, reauth):
    """Use the actual issuer and retain usable cleanup credentials on failure."""
    cleanup_pair = None
    refresh_unvalidated = False
    try:
        status, data = probe.request(replica["origin"], "/api/v1/auth/login", body={
            "email": secret("F02_SYNTHETIC_EMAIL"), "password": secret("F02_SYNTHETIC_PASSWORD")})
        probe.check(replica["id"] + ":actual-login", status, 200)
        if isinstance(data, dict) and isinstance(data.get("data"), dict) and data["data"].get("mfaRequired"):
            raise Blocked("MFA-enabled synthetic account requires reviewed browser/device ceremony")
        pair = token_pair(data, "login")
        cleanup_pair = pair
        verify(pair["accessToken"], {kid: signing}, probe.m["tenant"], "jakeai-service", int(time.time()))
        probe.introspect(replica, pair["accessToken"], service, label="actual-issuer-key-and-state")
        probe.consumer(pair["accessToken"], 200, replica["id"] + ":actual-issued-access")
        if reauth:
            refresh_unvalidated = True
            status, refreshed = probe.request(replica["origin"], "/api/v1/auth/refresh-token", body={"refreshToken": pair["refreshToken"]})
            probe.check(replica["id"] + ":actual-refresh", status, 200)
            replacement = token_pair(refreshed, "refresh")
            verify(replacement["accessToken"], {kid: signing}, probe.m["tenant"], "jakeai-service", int(time.time()))
            probe.introspect(replica, replacement["accessToken"], service, label="refreshed-state")
            cleanup_pair = replacement
            refresh_unvalidated = False
    finally:
        failed = sys.exc_info()[0] is not None
        if not cleanup_session(probe, replica, cleanup_pair, refresh_unvalidated) and not failed:
            raise Blocked("synthetic-session cleanup unresolved")


def run(probe, phase):
    m = validate(probe.m)
    now = int(time.time())
    if phase == "overlap" and not m["last_old_issuance_unix"] <= now < min(m["last_old_issuance_unix"] + 930, m["service_overlap_until_unix"]):
        raise Blocked("outside actual signing/service overlap window")
    if phase in ("retired", "rollback") and now < max(m["last_old_issuance_unix"] + 930, m["service_overlap_until_unix"]):
        raise Blocked("actual retirement deadline has not elapsed")
    previous = phase == "baseline"
    kid = m["previous_kid"] if previous else m["current_kid"]
    signing = secret("F02_PREVIOUS_SIGNING_KEY" if previous else "F02_CURRENT_SIGNING_KEY")
    token = secret("F02_ACCESS_TOKEN")
    claims = verify(token, {kid: signing}, m["tenant"], "jakeai-service", now)
    service = (m["previous_service_kid"], secret("F02_PREVIOUS_SERVICE_KEY")) if previous else (m["service_kid"], secret("F02_CURRENT_SERVICE_KEY"))
    outage = phase in ("mysql-outage", "redis-outage")
    old_token = None
    if phase in ("overlap", "retired", "rollback"):
        old_token = secret("F02_PREVIOUS_ACCESS_TOKEN")
        if phase == "overlap":
            old_claims = verify(old_token, {m["previous_kid"]: secret("F02_PREVIOUS_SIGNING_KEY")}, m["tenant"], "jakeai-service", now)
            if old_claims["iat"] > m["last_old_issuance_unix"]:
                raise Blocked("old access token issued after recorded final old issuance")
    for replica in m["replicas"]:
        probe.introspect(replica, token, service, 503 if outage else 200)
        status, _ = probe.request(replica["origin"], "/api/v1/auth/me", token=token)
        probe.check(replica["id"] + ":protected-api", status, 503 if outage else 200)
        if outage:
            continue
        probe.introspect(replica, token, None, 401, label="missing-service")
        probe.introspect(replica, token, ("wrong", "invalid-synthetic"), 401, label="wrong-service")
        probe.introspect(replica, token, service, 403, tenant=m["foreign_tenant"], label="tenant-mismatch")
        for name, candidate in negatives(claims, kid, signing):
            # A signed foreign tenant disagrees with the explicitly expected tenant.
            expected = 403 if name == "wrong-tid" else 401
            probe.introspect(replica, candidate, service, expected, label=name)
        login_rehearsal(probe, replica, signing, kid, service, phase in ("reauth", "rollback"))
        if phase in ("overlap", "retired", "rollback"):
            expected = 200 if phase == "overlap" else 401
            probe.consumer(token, 200, replica["id"] + ":current-signing-control")
            probe.introspect(replica, old_token, service, 200 if phase == "overlap" else 401, label="captured-previous-access")
            probe.consumer(old_token, expected, "captured-previous-access")
            old_service = (m["previous_service_kid"], secret("F02_PREVIOUS_SERVICE_KEY"))
            probe.introspect(replica, token, old_service, 200 if phase == "overlap" else 401, label="previous-service")
            # Renew only challenge times, retaining the authoritative session and
            # grants. Paired current-key positives prevent expiry/dead state from
            # masquerading as retirement. Neither challenge is issuer-produced.
            issued = int(time.time())
            challenge_claims = dict(claims, iat=issued, nbf=issued, exp=issued + 900)
            current_challenge = signed(challenge_claims, kid, signing)
            probe.introspect(replica, current_challenge, service, label="current-signing-fresh-control")
            probe.consumer(current_challenge, 200, "current-signing-fresh-control")
            challenge = signed(challenge_claims, m["previous_kid"], secret("F02_PREVIOUS_SIGNING_KEY"))
            probe.introspect(replica, challenge, service, 200 if phase == "overlap" else 401, label="previous-signing-fresh-challenge")
            probe.consumer(challenge, expected, "previous-signing-fresh-challenge")
        if phase in ("reauth", "rollback"):
            legacy = secret("F02_LEGACY_ACCESS_TOKEN")
            status, _ = probe.request(replica["origin"], "/api/v1/auth/me", token=legacy)
            probe.check(replica["id"] + ":legacy-reauth-required", status, 401)
            probe.consumer(legacy, 401, "legacy-reauth-required")
    probe.consumer(token, 503 if outage else 200, phase)
    if not outage:
        for name, candidate in negatives(claims, kid, signing):
            probe.consumer(candidate, 401, name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--phase", choices=PHASES, default="overlap")
    parser.add_argument("--execute-reviewed-manifest-sha256")
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    result = {"manifest_sha256": digest, "phase": args.phase, "status": "BLOCKED",
              "boundary": "F02 probes only; browser/rollout/owner/runtime acceptance requires separate evidence",
              "cases": [], "observed_unix": int(time.time())}
    try:
        if not __debug__:
            raise Blocked("Python optimization disables the reference policy; use normal Python")
        manifest = validate(json.loads(raw))
        result["consumer_kind"] = manifest["consumer_kind"]
        if args.execute_reviewed_manifest_sha256 is None:
            result["status"] = "NOT_RUN"
            result["reason"] = "offline plan validated; execution requires explicit target authorization"
        else:
            if not hmac.compare_digest(args.execute_reviewed_manifest_sha256, digest):
                raise Blocked("manifest differs from reviewed target plan")
            probe = Probe(manifest)
            result["cases"] = probe.results
            run(probe, args.phase)
            result["status"] = "PROBES_PASS_ACCEPTANCE_PENDING"
    except (Blocked, AssertionError, ValueError, KeyError, TypeError, OSError, urllib.error.URLError) as error:
        # Never echo response bodies, exception text, tokens, credentials or URLs.
        result["reason"] = str(error) if isinstance(error, Blocked) else "probe/configuration error (details withheld)"
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in ("NOT_RUN", "PROBES_PASS_ACCEPTANCE_PENDING") else 2


if __name__ == "__main__":
    sys.exit(main())
