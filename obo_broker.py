"""azobo OBO credential broker.

Runs as its OWN user (e.g. `azobo-broker`), separate from the `azobo` user that
runs the MCP server + the arbitrary `az` subprocess. It is the ONLY process that
holds the OBO certificate — the key file is chmod 600 owned by azobo-broker, so
neither the server nor an `az rest --body @…` can read it. Callers reach the
broker over a local Unix socket and ask it to mint OBO tokens; the cert never
leaves this process and the user assertion never reaches the CLI subprocess.

Protocol — newline-delimited JSON over the socket, one request → one response:
  {"op":"register","assertion":"<jwt>"}        -> {"session":"<id>"}   (broker VALIDATES the assertion)
  {"op":"mint","session":"<id>","scopes":[…]}  -> {"token":"…","expires_on":N}
  {"op":"end","session":"<id>"}                -> {"ok":true}
errors -> {"error":"…"}

The socket is reachable by anything in the shared `azobo` group, so the broker does
not assume a trusted caller: `register` validates the assertion itself, and `mint`
requires a 128-bit session id it can't guess. (There is intentionally no
mint-by-raw-assertion op — minting always goes through a registered session.)

Why sessions: the server holds the user's bearer; it registers a session and
hands the `az` subprocess only an opaque, short-lived session id — so the
subprocess can mint tokens for THIS user (its own authority, ~minutes, online,
revocable) but never holds the assertion or the cert. Stealing anything reachable
from the CLI no longer yields the shared, offline-usable crown-jewel cert.
"""
import json, os, secrets, socket, threading, time

TENANT = os.environ["AZOBO_TENANT_ID"]
CLIENT = os.environ["AZOBO_CLIENT_ID"]
KEY = os.environ["AZOBO_CERT_KEY"]
CERT = os.environ["AZOBO_CERT_PUB"]
THUMB = os.environ["AZOBO_CERT_THUMBPRINT"]
SOCKET_PATH = os.environ.get("AZOBO_BROKER_SOCKET", "/run/azobo/broker.sock")
SESSION_TTL = int(os.environ.get("AZOBO_SESSION_TTL", "300"))

# The broker is the credential boundary, so it validates assertions ITSELF at
# register (signature via tenant JWKS, audience, issuer, scope, client allow-list)
# — not relying on the MCP server having done so. Defense in depth: even a direct
# socket caller can't register a forged/out-of-policy assertion.
VALIDATE = os.environ.get("AZOBO_VALIDATE_TOKENS", "true").lower() in ("1", "true", "yes")
AUDIENCE = [x for x in (CLIENT, f"api://{CLIENT}", os.environ.get("AZOBO_AUDIENCE", "")) if x]
REQUIRED_SCOPE = os.environ.get("AZOBO_REQUIRED_SCOPE", "").strip()
ALLOWED_CLIENTS = [x.strip() for x in os.environ.get("AZOBO_ALLOWED_CLIENTS", "").split(",") if x.strip()]

_sessions = {}          # session_id -> (assertion, expiry_ts)
_lock = threading.Lock()
_app = None             # MSAL confidential client (holds the cert) — built lazily


def _get_app():
    """Build the confidential client once. The cert is read HERE and nowhere else."""
    global _app
    if _app is None:
        import msal
        _app = msal.ConfidentialClientApplication(
            CLIENT, authority=f"https://login.microsoftonline.com/{TENANT}",
            client_credential={"private_key": open(KEY).read(), "thumbprint": THUMB,
                               "public_certificate": open(CERT).read()})
    return _app


_jwks = None
def _jwks_client():
    global _jwks
    if _jwks is None:
        from jwt import PyJWKClient
        _jwks = PyJWKClient(f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
    return _jwks

def _valid_assertion(assertion):
    """Verify an assertion is a real Entra token for this tenant+app+scope+client
    before we'll register a session for it. (Patched in tests.)"""
    if not VALIDATE:
        return True
    try:
        import jwt
        key = _jwks_client().get_signing_key_from_jwt(assertion).key
        claims = jwt.decode(assertion, key, algorithms=["RS256"], audience=AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("iss", "") not in (f"https://login.microsoftonline.com/{TENANT}/v2.0",
                                          f"https://sts.windows.net/{TENANT}/"):
            return False
        if REQUIRED_SCOPE and REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            return False
        if ALLOWED_CLIENTS and (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
            return False
        return True
    except Exception:
        return False

def _mint(assertion, scopes):
    """Do the OBO exchange. Raises on failure. (Patched in tests.)

    Token caching is MSAL's job and happens HERE, for free: this one long-lived app
    holds an in-memory cache keyed by (assertion, scopes). acquire_token_on_behalf_of
    returns a cached token until ~5 min before expiry, then refreshes — so repeated
    mints for the same user+scope DON'T hit Entra. (The old per-command wrapper built
    a fresh app each call, so its cache was always cold; centralizing the cert in this
    persistent broker is also what gives us a real shared token cache.) In-memory by
    design — OBO tokens are never persisted to disk; a broker restart just re-warms."""
    r = _get_app().acquire_token_on_behalf_of(user_assertion=assertion, scopes=list(scopes))
    if "access_token" not in r:
        raise RuntimeError(f"OBO failed: {r.get('error')}: {str(r.get('error_description'))[:160]}")
    return r["access_token"], int(time.time()) + int(r.get("expires_in", 3000))


def _reap(now):
    for sid in [s for s, (_a, exp) in _sessions.items() if exp <= now]:
        _sessions.pop(sid, None)


def handle_request(req):
    """Pure protocol handler (no socket) — easy to unit test."""
    if not isinstance(req, dict):
        return {"error": "bad request"}
    op = req.get("op")
    now = time.time()
    if op == "register":
        a = req.get("assertion") or ""
        if not a:
            return {"error": "assertion required"}
        if not _valid_assertion(a):
            return {"error": "assertion failed validation (signature/audience/issuer/scope/client)"}
        sid = secrets.token_hex(16)
        with _lock:
            _reap(now)
            _sessions[sid] = (a, now + SESSION_TTL)
        return {"session": sid}
    if op == "end":
        with _lock:
            _sessions.pop(req.get("session", ""), None)
        return {"ok": True}
    if op == "mint":
        with _lock:
            _reap(now)
            v = _sessions.get(req.get("session", ""))
        if not v:
            return {"error": "unknown or expired session"}
        assertion = v[0]
    else:
        return {"error": f"unknown op {op!r}"}
    scopes = req.get("scopes") or []
    if not scopes:
        return {"error": "scopes required"}
    try:
        token, exp = _mint(assertion, scopes)
        return {"token": token, "expires_on": exp}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}


def _serve_conn(conn):
    try:
        conn.settimeout(30)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 1 << 20:  # a JWT assertion is a few KB; cap the line
                conn.sendall(b'{"error":"request too large"}\n'); return
        req = json.loads(buf.split(b"\n", 1)[0] or b"{}")
        resp = handle_request(req)
        conn.sendall((json.dumps(resp) + "\n").encode())
    except Exception as e:
        try: conn.sendall((json.dumps({"error": f"{type(e).__name__}"}) + "\n").encode())
        except Exception: pass
    finally:
        conn.close()


def serve(path=SOCKET_PATH):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o660)  # group (shared azobo group) may connect; world may not
    s.listen(64)
    print(f"obo-broker: listening on {path} (cert held here only)", flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=_serve_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve()
