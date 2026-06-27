import os, re, shlex, shutil, subprocess, tempfile, json, time, uuid, base64, threading
import urllib.request, urllib.error, msal
from collections import OrderedDict
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Anything we DO write (only the audit log) is owner-only.
os.umask(0o077)

PUBLIC_HOST = os.environ.get("AZOBO_PUBLIC_HOST", "localhost")
TENANT = os.environ["AZOBO_TENANT_ID"]; CLIENT = os.environ["AZOBO_CLIENT_ID"]
THUMB = os.environ["AZOBO_CERT_THUMBPRINT"]
KEY = os.environ["AZOBO_CERT_KEY"]; CERT = os.environ["AZOBO_CERT_PUB"]
DEFAULT_SUB = os.environ.get("AZOBO_DEFAULT_SUBSCRIPTION", "")
VENV_PY = os.environ.get("AZOBO_PYTHON", "/opt/azobo/venv/bin/python")
AZOBO = os.environ.get("AZOBO_WRAPPER", "/opt/azobo/azobo")
TIMEOUT = int(os.environ.get("AZOBO_TIMEOUT", "150"))
MAX_OUT = int(os.environ.get("AZOBO_MAX_OUTPUT_CHARS", "100000"))  # ~25k tokens; full output kept in memory
AUDIT = os.environ.get("AZOBO_AUDIT_LOG", "/var/lib/azobo/audit.log")

# Full command output is retained IN MEMORY only (never written to disk) so a
# read_output can page it — bounded by count + TTL, evicted oldest-first. Lost on
# restart by design: it is a retrieval aid, not a record (the audit log is).
OUT_MAX = int(os.environ.get("AZOBO_OUTPUT_MAX_ENTRIES", "300"))
OUT_TTL = int(os.environ.get("AZOBO_OUTPUT_TTL_SECONDS", "1800"))

# Server-enforced read-only mode (defense-in-depth ON TOP OF per-user RBAC, which
# is the real boundary). When on: Graph is GET-only and mutating `az` verbs are
# refused. Default off — the deployment opts in.
READONLY = os.environ.get("AZOBO_READONLY", "").lower() in ("1", "true", "yes")

# Verify the incoming bearer is a real Entra token for THIS tenant+app before
# trusting ANY claim (signature/audience/issuer/expiry). Default ON. Turning it
# off trusts unsigned JWT payloads — lab / trusted-network only.
VALIDATE = os.environ.get("AZOBO_VALIDATE_TOKENS", "true").lower() in ("1", "true", "yes")
AUDIENCE = [x for x in (CLIENT, f"api://{CLIENT}", os.environ.get("AZOBO_AUDIENCE", "")) if x]

# Azure CLI verbs that mutate — refused in read-only mode. Best-effort (the CLI
# has no clean read/write taxonomy); RBAC remains the authoritative boundary.
_MUTATING = {"create", "delete", "update", "set", "add", "remove", "purge", "regenerate",
             "reset", "restart", "start", "stop", "deallocate", "import", "upload", "attach",
             "detach", "enable", "disable", "assign", "grant", "revoke", "move", "run-command",
             "invoke", "generate", "rotate", "renew", "approve", "reject", "wait", "lock"}

try:
    os.makedirs(os.path.dirname(AUDIT) or ".", exist_ok=True)
except OSError:
    pass  # audit writes are best-effort; don't let a perms hiccup block startup
_lock = threading.Lock()
_outputs = OrderedDict()  # output_id -> (owner_oid, text, ts)

mcp = FastMCP("azure-obo",
    instructions=("Operate Azure and Entra AS THE SIGNED-IN USER (per-user on-behalf-of). "
        "az_run = full Azure CLI (management plane AND `az ad` directory); graph_run = raw "
        "Microsoft Graph REST; read_output = page a previous command's full output if it was "
        "truncated. Everything is bounded by the user's own Azure RBAC + Entra role — a 403 / "
        "AuthorizationFailed is their permission boundary, not a bug."),
    host="127.0.0.1", port=8782, stateless_http=False, json_response=False, streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        allowed_hosts=[PUBLIC_HOST, f"{PUBLIC_HOST}:443", "127.0.0.1:8782", "localhost:8782"],
        allowed_origins=[f"https://{PUBLIC_HOST}", "http://127.0.0.1:8782"]))

def _bearer(ctx):
    try:
        h = ctx.request_context.request.headers.get("authorization", "") or ""
        return h[7:].strip() if h[:7].lower() == "bearer " else h.strip()
    except Exception:
        return ""

_graph = None
def _graph_app():
    """Confidential client for the Graph OBO exchange — built once (cert/key read
    a single time at first use, not per request)."""
    global _graph
    if _graph is None:
        _graph = msal.ConfidentialClientApplication(
            CLIENT, authority=f"https://login.microsoftonline.com/{TENANT}",
            client_credential={"private_key": open(KEY).read(), "thumbprint": THUMB,
                               "public_certificate": open(CERT).read()})
    return _graph

_jwks = None
def _jwks_client():
    global _jwks
    if _jwks is None:
        from jwt import PyJWKClient
        _jwks = PyJWKClient(f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
    return _jwks

def _ident(c):
    """(owner_key, display) from claims. Owner = oid (immutable, always present —
    the right key for output ownership); display = upn for the human-readable audit."""
    owner = c.get("oid") or c.get("upn") or c.get("preferred_username") or "?"
    display = c.get("preferred_username") or c.get("upn") or c.get("oid") or "?"
    return (owner, display)

def _identity(bearer):
    """Return (owner_oid, display) ONLY after the token is cryptographically verified
    for this tenant+app (signature via JWKS, audience, issuer, expiry). Returns None
    when the token fails validation — callers MUST reject. This is the access control
    for read_output (which never does an OBO exchange, so it can't lean on Entra to
    reject a forged token like az_run/graph_run implicitly do). When
    AZOBO_VALIDATE_TOKENS is off, falls back to the unverified payload (lab/trusted only)."""
    if not bearer:
        return None
    if not VALIDATE:
        try:
            p = bearer.split('.')[1]; p += '=' * (-len(p) % 4)
            return _ident(json.loads(base64.urlsafe_b64decode(p)))
        except Exception:
            return ("?", "?")
    try:
        import jwt
        signing = _jwks_client().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, signing, algorithms=["RS256"], audience=AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("iss", "") not in (f"https://login.microsoftonline.com/{TENANT}/v2.0",
                                          f"https://sts.windows.net/{TENANT}/"):
            return None
        return _ident(claims)
    except Exception:
        return None

def _audit(who, tool, cmd, rc, dur, n, oid):
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "who": who,
                      "tool": tool, "cmd": cmd[:500], "rc": rc, "dur": round(dur, 2),
                      "out_chars": n, "output_id": oid})
    try:
        with _lock, open(AUDIT, "a") as f:
            f.write(rec + "\n")
    except Exception:
        pass

def _store(who, out):
    """Retain full output in memory (owner-stamped), evicting expired + oldest."""
    oid = uuid.uuid4().hex[:12]; now = time.time()
    with _lock:
        _outputs[oid] = (who, out, now)
        for k in [k for k, (_o, _t, ts) in _outputs.items() if now - ts > OUT_TTL]:
            _outputs.pop(k, None)
        while len(_outputs) > OUT_MAX:
            _outputs.popitem(last=False)
    return oid

def _finalize(owner, who, tool, cmd, out, rc, dur):
    """Retain full output in memory (owner-stamped by oid), audit, return capped view."""
    oid = _store(owner, out)
    _audit(who, tool, cmd, rc, dur, len(out), oid)
    if len(out) <= MAX_OUT:
        return out
    return out[:MAX_OUT] + (f"\n\n[…TRUNCATED: returned {MAX_OUT} of {len(out)} chars. Full output "
        f"held in memory as output_id='{oid}' (expires in ~{OUT_TTL // 60}m). Read the rest with "
        f"read_output(output_id='{oid}', offset={MAX_OUT}), or re-run with a narrower --query / -o tsv / --top.]")

@mcp.tool()
def az_run(command: str, ctx: Context) -> str:
    """Run a raw Azure CLI command AS YOU (the signed-in user, via on-behalf-of) and return its output.
    Write it as in a terminal but WITHOUT the leading `az` (e.g. `network vnet show -g RG -n NAME -o json`,
    `vm list -o table`, `group list --query "[].name"`, `ad app list`). Full az surface, under YOUR Azure
    RBAC. Directory works too: `ad app/sp/user/group ...`. For any other endpoint/audience use
    `rest --method GET --url <url> --resource <resource>`.
    Rules: ONE command per call (no `&&`/pipes/`--follow`/`--watch`); filter with `--query` (JMESPath) and
    `-o json/table/tsv`. Large output is truncated in the reply but FULLY retained — page it with
    read_output(output_id). A 403/AuthorizationFailed/empty result outside your scope is your permission
    boundary, not an error to route around. Writes (create/delete, role/app changes) are real."""
    a = _bearer(ctx)
    if not a:
        return json.dumps({"error": "no bearer token on request"})
    ident = _identity(a)
    if ident is None:
        return json.dumps({"error": "unauthenticated: bearer failed validation (signature/audience/issuer/expiry)"})
    owner, who = ident
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return json.dumps({"error": f"could not parse command: {e}"})
    if argv and argv[0] in ("interactive", "ssh"):
        return json.dumps({"error": f"`az {argv[0]}` is interactive/never-returns and is not supported here. "
                                    "Use --no-wait + poll, or a bounded query."})
    if any(t in ("--follow", "--watch") for t in argv):
        return json.dumps({"error": "--follow/--watch never return here. Fetch a bounded snapshot "
                                    "(e.g. --lines N) or use --no-wait + poll."})
    if READONLY and any(t in _MUTATING for t in argv):
        return json.dumps({"error": "server is in read-only mode (AZOBO_READONLY): this command appears "
                                    "to mutate. Only read operations (list/show/get/...) are permitted."})
    cfg = tempfile.mkdtemp(prefix="azcfg-"); t0 = time.time(); rc = -1
    try:
        env = dict(os.environ, AZOBO_ASSERTION=a, AZOBO_CLIENT_ID=CLIENT, AZOBO_KEY=KEY, AZOBO_CERT=CERT,
                   AZOBO_THUMB=THUMB, AZURE_TENANT_ID=TENANT, AZURE_SUBSCRIPTION_ID=DEFAULT_SUB,
                   AZURE_CONFIG_DIR=cfg, AZURE_EXTENSION_DIR=os.path.join(cfg, "ext"),
                   AZURE_CORE_DISABLE_DYNAMIC_INSTALL="yes", AZURE_CORE_COLLECT_TELEMETRY="no")
        r = subprocess.run([VENV_PY, AZOBO] + argv, env=env, capture_output=True, text=True, timeout=TIMEOUT)
        rc = r.returncode
        out = (r.stdout if rc == 0 else (r.stdout + r.stderr)).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        out = json.dumps({"error": f"timed out after {TIMEOUT}s — for long ops use --no-wait + poll status"})
    finally:
        shutil.rmtree(cfg, ignore_errors=True)
    return _finalize(owner, who, "az_run", command, out, rc, time.time() - t0)

@mcp.tool()
def graph_run(path: str, ctx: Context, method: str = "GET", body: str = "", allow_write: bool = False) -> str:
    """Call Microsoft Graph AS YOU (per-user OBO) — the directory tool (Entra/AAD apps, service
    principals, users, groups). path e.g. `applications`, `servicePrincipals?$top=10`, `me` (v1.0 assumed).
    method GET (default)/POST/PATCH/DELETE; mutations require allow_write=true; body = JSON string.
    Note: `az ad ...` and `az rest` (via az_run) also reach Graph. Large output is truncated + retained
    (page with read_output)."""
    a = _bearer(ctx)
    if not a:
        return json.dumps({"error": "no bearer token on request"})
    ident = _identity(a)
    if ident is None:
        return json.dumps({"error": "unauthenticated: bearer failed validation (signature/audience/issuer/expiry)"})
    owner, who = ident
    if method.upper() != "GET" and (READONLY or not allow_write):
        msg = "server is in read-only mode (AZOBO_READONLY)" if READONLY else f"{method} is a write — pass allow_write=true to permit"
        return json.dumps({"error": msg})
    t0 = time.time()
    try:
        r = _graph_app().acquire_token_on_behalf_of(
            user_assertion=a, scopes=["https://graph.microsoft.com/.default"])
    except Exception as e:
        return json.dumps({"error": f"graph OBO error: {type(e).__name__}: {str(e)[:160]}"})
    if "access_token" not in r:
        return json.dumps({"error": f"graph OBO failed: {r.get('error')}: {str(r.get('error_description'))[:160]}"})
    p = path.lstrip("/"); p = p if p.startswith(("v1.0/", "beta/")) else "v1.0/" + p
    req = urllib.request.Request("https://graph.microsoft.com/" + p, data=(body.encode() if body else None),
        method=method.upper(), headers={"Authorization": "Bearer " + r["access_token"],
                                        "Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        out = resp.read().decode() or json.dumps({"status": resp.status}); rc = 0
    except urllib.error.HTTPError as e:
        out = json.dumps({"status": e.code, "error": json.loads(e.read() or b"{}")}); rc = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        out = json.dumps({"error": f"graph request failed: {type(e).__name__}: {str(e)[:160]}"}); rc = -1
    return _finalize(owner, who, "graph_run", f"{method} {path}", out, rc, time.time() - t0)

@mcp.tool()
def read_output(output_id: str, ctx: Context, offset: int = 0, max_chars: int = 0) -> str:
    """Read (more of) a previous command's FULL retained output when az_run/graph_run truncated it.
    Pass the output_id from the truncation note. offset = start char; max_chars = how many (default = cap).
    Only the user who produced the output can read it; output is held in memory and expires."""
    a = _bearer(ctx)
    ident = _identity(a)
    if ident is None:
        return json.dumps({"error": "unauthenticated: bearer failed validation"})
    caller_owner, _who = ident
    if not re.fullmatch(r"[0-9a-f]{1,32}", output_id or ""):
        return json.dumps({"error": "bad output_id"})
    now = time.time()
    with _lock:
        v = _outputs.get(output_id)
        if v and now - v[2] > OUT_TTL:
            _outputs.pop(output_id, None); v = None
    if not v:
        return json.dumps({"error": "output_id not found (expired/evicted or wrong id)"})
    owner, data, _ts = v
    if owner != caller_owner:
        return json.dumps({"error": "that output_id belongs to another user"})
    m = max_chars or MAX_OUT; chunk = data[offset:offset + m]; end = offset + len(chunk)
    more = (f"\n\n[chars {offset}-{end} of {len(data)}; more: read_output('{output_id}', offset={end})]"
            if end < len(data) else "")
    return chunk + more

from mcp import types as _t
for _rt in (_t.ListResourcesRequest, _t.ReadResourceRequest, _t.ListResourceTemplatesRequest,
            _t.ListPromptsRequest, _t.GetPromptRequest, _t.SubscribeRequest, _t.UnsubscribeRequest):
    mcp._mcp_server.request_handlers.pop(_rt, None)

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
