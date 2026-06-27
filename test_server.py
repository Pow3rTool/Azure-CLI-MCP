"""Unit tests for the security-load-bearing helpers: identity derivation, the
in-memory output store's owner isolation, and the truncation contract.

Run:  python test_server.py    (or: pytest test_server.py)

These set dummy env + AZOBO_VALIDATE_TOKENS=false so no network/JWKS is needed;
the JWT-validation path itself is integration-tested against a live tenant.
"""
import base64, json, os, tempfile

# Minimal env so server.py imports (it reads required vars at import time).
os.environ.setdefault("AZOBO_TENANT_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("AZOBO_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
os.environ.setdefault("AZOBO_CERT_THUMBPRINT", "AABB")
os.environ.setdefault("AZOBO_CERT_KEY", "/dev/null")
os.environ.setdefault("AZOBO_CERT_PUB", "/dev/null")
os.environ["AZOBO_VALIDATE_TOKENS"] = "false"           # exercise the payload path, no JWKS
os.environ["AZOBO_MAX_OUTPUT_CHARS"] = "50"             # make truncation testable
os.environ["AZOBO_AUDIT_LOG"] = os.path.join(tempfile.mkdtemp(), "audit.log")

import server  # noqa: E402


def _jwt(claims):
    """A signature-less JWT (header.payload.sig) — what the unverified path parses."""
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg':'none'})}.{seg(claims)}.x"


def test_identity_prefers_immutable_oid():
    owner, display = server._identity(_jwt({"oid": "OID-1", "preferred_username": "alice@corp"}))
    assert owner == "OID-1"                 # ownership keyed on the immutable oid
    assert display == "alice@corp"          # display is the friendly upn


def test_identity_none_without_token():
    assert server._identity("") is None


def test_output_store_owner_isolation():
    oid = server._store("OID-alice", "secret-output")
    with server._lock:
        owner, text, _ts = server._outputs[oid]
    assert owner == "OID-alice" and text == "secret-output"
    # A different caller's oid must not match the stored owner.
    assert owner != "OID-bob"


def test_finalize_truncates_but_keeps_full():
    full = "x" * 200                        # > AZOBO_MAX_OUTPUT_CHARS (50)
    view = server._finalize("OID-a", "alice@corp", "az_run", "vm list", full, 0, 0.1)
    assert "TRUNCATED" in view and len(view) < len(full) + 400
    # The full text is retained in memory under the advertised output_id.
    oid = view.split("output_id='")[1].split("'")[0]
    with server._lock:
        owner, text, _ts = server._outputs[oid]
    assert text == full and owner == "OID-a"


def test_finalize_short_output_untouched():
    view = server._finalize("OID-a", "alice@corp", "az_run", "x", "short", 0, 0.0)
    assert view == "short" and "TRUNCATED" not in view


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
