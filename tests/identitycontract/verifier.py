"""Independent Python reference for agreed Jake v1 policy, NOT its runtime verifier.

Standard-library HMAC verifies Go-issued synthetic bytes. No environment secrets,
network, production tokens, permissive algorithm fallback or third-party JWT code.
"""
import base64
import hashlib
import hmac
import json
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


def decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def verify(token, keys, tenant, audience, now, retired=None):
    header_bytes, claim_bytes, signature = token.split(".")
    header = json.loads(decode(header_bytes), object_pairs_hook=unique_object)
    claims = json.loads(decode(claim_bytes), object_pairs_hook=unique_object)
    assert header["alg"] == "HS256" and header["kid"] in keys
    assert not retired or now < retired.get(header["kid"], float("inf"))
    key = base64.b64decode(keys[header["kid"]], validate=True)
    expected = hmac.new(key, f"{header_bytes}.{claim_bytes}".encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(expected, decode(signature))
    required = {"contract_ver", "iss", "aud", "sub", "uid", "type", "tid", "exp", "iat", "nbf", "jti", "sid", "pwdver", "auth_epoch", "perms"}
    assert required <= claims.keys() and all(claims[k] is not None for k in required)
    assert not {"tenant_id", "permissions", "roles", "scopes", "id"}.intersection(claims)
    for name in ("contract_ver", "uid", "pwdver", "auth_epoch", "exp", "iat", "nbf"):
        assert type(claims[name]) is int and claims[name] >= 0
    assert claims["contract_ver"] == 1 and claims["iss"] == "finnapigo" and claims["type"] == "access"
    assert claims["uid"] > 0 and claims["sub"] == str(claims["uid"])
    assert isinstance(claims["tid"], str) and claims["tid"].strip() and claims["tid"] == tenant
    assert all(isinstance(claims[k], str) and claims[k] for k in ("jti", "sid"))
    assert isinstance(claims["perms"], list) and all(isinstance(p, str) for p in claims["perms"])
    assert 0 < claims["exp"] - claims["iat"] <= 900
    assert claims["iat"] <= claims["nbf"] <= claims["exp"]
    assert claims["iat"] <= now + 30 and claims["nbf"] <= now + 30 and now < claims["exp"] + 30
    aud = claims["aud"]
    if isinstance(aud, str):
        aud = [aud]
    assert audience in ("finnapigo-api", "jakeai-service")
    assert isinstance(aud, list) and len(aud) in (1, 2) and len(set(aud)) == len(aud)
    assert "finnapigo-api" in aud and audience in aud and set(aud) <= {"finnapigo-api", "jakeai-service"}
    return claims


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    for case in data["fixtures"]:
        try:
            verify(case["Token"], data["keys"], case["Tenant"], case["Audience"], case["Now"], data.get("retired"))
            active = True
        except (AssertionError, ValueError, TypeError, KeyError):
            active = False
        assert active == case["Active"], f"Python verdict mismatch: {case['Name']}"
    print(f"PASS: {len(data['fixtures'])} Go-issued synthetic fixtures under independent Jake v1 reference policy")


if __name__ == "__main__":
    main()
