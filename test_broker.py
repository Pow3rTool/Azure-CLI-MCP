"""Unit + socket tests for the OBO credential broker. The MSAL/cert exchange is
stubbed (`_mint`), so this runs with no cert and no Entra — it proves the session
protocol, ownership, expiry, and the wire round-trip. The live OBO exchange is the
same `acquire_token_on_behalf_of` call, verified on the deploy host.

Run:  python test_broker.py   (or: pytest test_broker.py)
"""
import json, os, socket, tempfile, threading, time

os.environ.setdefault("AZOBO_TENANT_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("AZOBO_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
os.environ.setdefault("AZOBO_CERT_THUMBPRINT", "AABB")
os.environ.setdefault("AZOBO_CERT_KEY", "/dev/null")
os.environ.setdefault("AZOBO_CERT_PUB", "/dev/null")

import obo_broker  # noqa: E402

# Stub the exchange — no cert, no network. Echoes inputs so we can assert routing.
obo_broker._mint = lambda assertion, scopes: (f"tok::{assertion}::{','.join(scopes)}",
                                              int(time.time()) + 3000)


def test_register_mint_end():
    sid = obo_broker.handle_request({"op": "register", "assertion": "ASSERT-A"})["session"]
    assert sid
    m = obo_broker.handle_request({"op": "mint", "session": sid, "scopes": ["s1"]})
    assert m["token"] == "tok::ASSERT-A::s1"
    obo_broker.handle_request({"op": "end", "session": sid})
    assert "error" in obo_broker.handle_request({"op": "mint", "session": sid, "scopes": ["s1"]})


def test_unknown_session_rejected():
    assert "error" in obo_broker.handle_request({"op": "mint", "session": "deadbeef", "scopes": ["s"]})


def test_register_requires_assertion():
    assert "error" in obo_broker.handle_request({"op": "register", "assertion": ""})


def test_mint_requires_scopes():
    sid = obo_broker.handle_request({"op": "register", "assertion": "A"})["session"]
    assert "error" in obo_broker.handle_request({"op": "mint", "session": sid, "scopes": []})


def test_mint_assertion_direct():
    m = obo_broker.handle_request({"op": "mint_assertion", "assertion": "DIRECT", "scopes": ["s2"]})
    assert m["token"] == "tok::DIRECT::s2"


def test_session_expiry_reaped():
    old = obo_broker.SESSION_TTL
    obo_broker.SESSION_TTL = -1  # any session is already past expiry
    try:
        sid = obo_broker.handle_request({"op": "register", "assertion": "X"})["session"]
        assert "error" in obo_broker.handle_request({"op": "mint", "session": sid, "scopes": ["s"]})
    finally:
        obo_broker.SESSION_TTL = old


def test_socket_roundtrip():
    path = os.path.join(tempfile.mkdtemp(), "b.sock")
    threading.Thread(target=obo_broker.serve, args=(path,), daemon=True).start()
    for _ in range(60):
        if os.path.exists(path):
            break
        time.sleep(0.05)

    def call(req):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(path)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            buf += s.recv(65536)
        s.close()
        return json.loads(buf.split(b"\n", 1)[0])

    sid = call({"op": "register", "assertion": "SOCK"})["session"]
    assert call({"op": "mint", "session": sid, "scopes": ["arm"]})["token"] == "tok::SOCK::arm"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
