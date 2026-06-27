import os, re, shlex, shutil, signal, socket, subprocess, tempfile, json, time, uuid, base64, threading
from collections import OrderedDict
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Anything we DO write (only the audit log) is owner-only.
os.umask(0o077)

PUBLIC_HOST = os.environ.get("AZOBO_PUBLIC_HOST", "localhost")
TENANT = os.environ["AZOBO_TENANT_ID"]; CLIENT = os.environ["AZOBO_CLIENT_ID"]
DEFAULT_SUB = os.environ.get("AZOBO_DEFAULT_SUBSCRIPTION", "")
VENV_PY = os.environ.get("AZOBO_PYTHON", "/opt/azobo/venv/bin/python")
AZOBO = os.environ.get("AZOBO_WRAPPER", "/opt/azobo/azobo")
# The OBO cert lives ONLY in the broker process (separate user); the server and the
# `az` subprocess mint tokens over this local socket and never read the key.
BROKER_SOCKET = os.environ.get("AZOBO_BROKER_SOCKET", "/run/azobo/broker.sock")
TIMEOUT = int(os.environ.get("AZOBO_TIMEOUT", "150"))
MAX_OUT = int(os.environ.get("AZOBO_MAX_OUTPUT_CHARS", "100000"))  # ~25k tokens; full output kept in memory
AUDIT = os.environ.get("AZOBO_AUDIT_LOG", "/var/lib/azobo/audit.log")

# Hard ceiling on bytes CAPTURED from a single command (stdout+stderr). Enforced
# WHILE reading — the child is killed once it exceeds this, so a runaway
# `az ... download` can't buffer gigabytes into RAM before MAX_OUT (which only
# trims what we RETURN) ever applies.
MAX_CAPTURE = int(os.environ.get("AZOBO_MAX_CAPTURE_BYTES", str(20 * 1024 * 1024)))  # 20 MB

# Full captured output is retained IN MEMORY only (never written to disk) so a
# read_output can page it — bounded by entry count, TOTAL bytes, and TTL; evicted
# oldest-first. Lost on restart by design: a retrieval aid, not a record (audit is).
OUT_MAX = int(os.environ.get("AZOBO_OUTPUT_MAX_ENTRIES", "300"))
OUT_MAX_BYTES = int(os.environ.get("AZOBO_OUTPUT_MAX_BYTES", str(100 * 1024 * 1024)))  # 100 MB total
OUT_TTL = int(os.environ.get("AZOBO_OUTPUT_TTL_SECONDS", "1800"))

# Server-enforced read-only mode (defense-in-depth ON TOP OF per-user RBAC, which
# is the real boundary). When on: mutating `az` verbs (incl. rest/invoke non-GET)
# are refused. Default off — the deployment opts in (example env ships it ON).
READONLY = os.environ.get("AZOBO_READONLY", "").lower() in ("1", "true", "yes")

# Verify the incoming bearer is a real Entra token for THIS tenant+app before
# trusting ANY claim (signature/audience/issuer/expiry). Default ON. Turning it
# off trusts unsigned JWT payloads — lab / trusted-network only.
VALIDATE = os.environ.get("AZOBO_VALIDATE_TOKENS", "true").lower() in ("1", "true", "yes")
AUDIENCE = [x for x in (CLIENT, f"api://{CLIENT}", os.environ.get("AZOBO_AUDIENCE", "")) if x]

# Caller authorization (beyond aud/iss/exp). Multi-client tenants: a token another
# client obtains for THIS resource app would otherwise pass. Set these in prod.
REQUIRED_SCOPE = os.environ.get("AZOBO_REQUIRED_SCOPE", "").strip()
ALLOWED_CLIENTS = [x.strip() for x in os.environ.get("AZOBO_ALLOWED_CLIENTS", "").split(",") if x.strip()]

# Command denylist (egress/exfil control). e.g. "account get-access-token" to remove
# the raw-token-to-stdout primitive. (`rest` is handled by the domain allow-list below,
# not a blanket deny, so legit raw-Graph/ARM still works.)
DENY_CMDS = [x.strip() for x in os.environ.get("AZOBO_DENY_COMMANDS", "").split(",") if x.strip()]

# `az rest`/`invoke` URL allow-list. An OBO token is only valid at the Microsoft
# first-party service it's audienced to — there is NO legitimate reason for `az rest`
# to target a non-Microsoft host, so anything else is exfiltration. We restrict the
# --url/--uri host to these domain suffixes; this keeps raw Graph/ARM working while
# killing `rest --url https://attacker… --body @file` token/file exfil. Empty = no
# restriction. (Residual: an attacker controlling an Azure resource — e.g. their own
# *.blob.core.windows.net — is bounded/traceable; use an egress proxy allow-list to
# close even that.)
# Commercial Azure/Microsoft only by default. Sovereign-cloud operators (US Gov,
# China, etc.) add their own suffixes via AZOBO_REST_ALLOWED_DOMAINS.
_DEFAULT_REST_DOMAINS = ("microsoft.com,microsoftonline.com,windows.net,"
                         "azure.com,azure.net")
# A blank/unset value falls back to the default — so copying a blank example can't
# silently DISABLE the exfil guard. To deliberately opt out, set it to "*".
_rest_env = os.environ.get("AZOBO_REST_ALLOWED_DOMAINS", "").strip()
REST_ALLOWED = ([] if _rest_env == "*" else
                [d.strip().lower() for d in (_rest_env or _DEFAULT_REST_DOMAINS).split(",") if d.strip()])

# Optional concurrency cap (backstop alongside MemoryMax). 0 = unlimited.
MAX_CONC = int(os.environ.get("AZOBO_MAX_CONCURRENCY", "0"))
import contextlib
_sem = threading.Semaphore(MAX_CONC) if MAX_CONC > 0 else None
def _nullctx():
    return contextlib.nullcontext()

# Audit: redact secret-bearing flag VALUES from the logged command. Matches a
# quoted (possibly multi-word) value OR a bare token, so `--value "a b"` doesn't
# leak its tail.
_SECRET_FLAG = re.compile(
    r'(--(?:password|secret|value|client-secret|certificate-password|body|headers?|'
    r'token|sas[-_]?token|account-key|connection-string|admin-password)[ =])'
    r'("[^"]*"|\'[^\']*\'|\S+)', re.I)
def _scrub(cmd):
    return _SECRET_FLAG.sub(lambda m: m.group(1) + "***", cmd or "")[:500]

def _rest_host_ok(argv):
    """For `rest`/`invoke`: extract the --url/--uri host and check it against the
    Microsoft/Azure allow-list. Returns (ok, host). No allow-list configured → ok."""
    if not REST_ALLOWED:
        return True, ""
    url = None
    for i, t in enumerate(argv):
        if t in ("--url", "--uri", "-u") and i + 1 < len(argv):
            url = argv[i + 1]
        elif t.startswith(("--url=", "--uri=")):
            url = t.split("=", 1)[1]
    if not url:
        return False, "(no --url)"
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        host = ""
    ok = bool(host) and any(host == d or host.endswith("." + d) for d in REST_ALLOWED)
    return ok, host

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
        "az_run = the full Azure CLI: management plane, the `az ad` directory (Entra apps, "
        "service principals, users, groups), AND any other endpoint via "
        "`rest --method GET --url <url>` (e.g. raw Microsoft Graph). read_output pages a "
        "previous command's full output if it was truncated. Everything is bounded by the "
        "user's own Azure RBAC + Entra role — a 403 / AuthorizationFailed is their permission "
        "boundary, not a bug."),
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

def _broker(req):
    """One request → one response against the OBO credential broker (the only holder
    of the cert). Newline-delimited JSON over the local Unix socket."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(TIMEOUT)
    try:
        s.connect(BROKER_SOCKET)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0] or b"{}")
    finally:
        s.close()

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
    for read_output (which never does an OBO exchange). When AZOBO_VALIDATE_TOKENS is
    off, falls back to the unverified payload (lab/trusted only)."""
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
        if REQUIRED_SCOPE and REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            return None
        if ALLOWED_CLIENTS and (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
            return None
        return _ident(claims)
    except Exception:
        return None

def _audit(who, tool, cmd, rc, dur, n, oid):
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "who": who,
                      "tool": tool, "cmd": _scrub(cmd), "rc": rc, "dur": round(dur, 2),
                      "out_chars": n, "output_id": oid})
    try:
        with _lock, open(AUDIT, "a") as f:
            f.write(rec + "\n")
    except Exception:
        pass

def _store(who, out):
    """Retain captured output in memory (owner-stamped), evicting expired, then
    oldest until BOTH the entry-count and total-byte budgets are satisfied."""
    oid = uuid.uuid4().hex[:12]; now = time.time()
    with _lock:
        _outputs[oid] = (who, out, now)
        for k in [k for k, (_o, _t, ts) in _outputs.items() if now - ts > OUT_TTL]:
            _outputs.pop(k, None)
        total = sum(len(v[1]) for v in _outputs.values())
        while _outputs and (len(_outputs) > OUT_MAX or total > OUT_MAX_BYTES):
            _k, (_o, _t, _ts) = _outputs.popitem(last=False)
            total -= len(_t)
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

def _mutates(argv):
    """Best-effort 'does this az command write?' for read-only mode. Catches the
    verb set AND `rest`/`invoke` with a non-GET --method (the hole a plain verb
    check misses — `az rest --method POST` is a write that no verb token reveals).
    Defense-in-depth only; per-user RBAC is the authoritative boundary."""
    if any(t in _MUTATING for t in argv):
        return True
    if argv and argv[0] in ("rest", "invoke"):
        m = "GET"
        for i, t in enumerate(argv):
            if t in ("--method", "-m") and i + 1 < len(argv):
                m = argv[i + 1]
            elif t.startswith("--method="):
                m = t.split("=", 1)[1]
        if m.upper() != "GET":
            return True
    return False

def _run_capped(argv, env, timeout, cap):
    """Run the wrapper, capturing stdout and stderr on SEPARATE pipes (so the caller
    keeps the rc==0 -> clean-stdout contract — az writes WARNING/deprecation lines to
    stderr even on success, and the agent json.loads our stdout). Binary-safe (raw
    bytes, decoded at the end). Total captured is capped at `cap` BYTES across both
    streams; the child's whole process group is SIGKILLed the instant it exceeds the
    cap, so a runaway download can't buffer gigabytes into RAM. Returns
    (stdout, stderr, rc, capped, timed_out)."""
    p = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)  # binary pipes
    out_buf, err_buf = [], []; total = [0]; capped = [False]; mu = threading.Lock()
    def drain(stream, buf):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                with mu:
                    room = cap - total[0]
                    if room > 0:
                        take = chunk[:room]; buf.append(take); total[0] += len(take)
                    if total[0] >= cap and not capped[0]:
                        capped[0] = True
                        try: os.killpg(p.pid, signal.SIGKILL)
                        except Exception: pass
                        return
        except Exception:
            pass
    threads = [threading.Thread(target=drain, args=(s, b), daemon=True)
               for s, b in ((p.stdout, out_buf), (p.stderr, err_buf))]
    for t in threads: t.start()
    timed_out = False
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True; rc = -1
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
        p.wait()
    for t in threads: t.join(timeout=5)
    return (b"".join(out_buf).decode(errors="replace"),
            b"".join(err_buf).decode(errors="replace"), rc, capped[0], timed_out)

@mcp.tool()
def az_run(command: str, ctx: Context) -> str:
    """Run a raw Azure CLI command AS YOU (the signed-in user, via on-behalf-of) and return its output.
    Write it as in a terminal but WITHOUT the leading `az` (e.g. `network vnet show -g RG -n NAME -o json`,
    `vm list -o table`, `group list --query "[].name"`, `ad app list`). Full az surface, under YOUR Azure
    RBAC. Directory works too: `ad app/sp/user/group ...`. For raw Microsoft Graph or any other
    endpoint/audience use `rest --method GET --url <url>` (e.g. `rest --url https://graph.microsoft.com/v1.0/me`).
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
    if READONLY and _mutates(argv):
        return json.dumps({"error": "server is in read-only mode (AZOBO_READONLY): this command appears "
                                    "to mutate (a write verb, or rest/invoke with a non-GET method). "
                                    "Only read operations are permitted."})
    joined = " ".join(argv)
    if any(joined == d or joined.startswith(d + " ") for d in DENY_CMDS):
        return json.dumps({"error": "that command is disabled on this server (AZOBO_DENY_COMMANDS)."})
    if argv and argv[0] in ("rest", "invoke"):
        ok, host = _rest_host_ok(argv)
        if not ok:
            return json.dumps({"error": f"az rest is restricted to Microsoft/Azure endpoints; host {host!r} "
                "is not allowed. OBO tokens are only valid at Microsoft first-party services — targeting "
                "anything else is rejected (AZOBO_REST_ALLOWED_DOMAINS)."})

    # Register a short-lived broker session for this user, and hand the subprocess
    # only the opaque session id — NOT the assertion and NOT the cert. The wrapper
    # mints tokens by presenting the session over the broker socket.
    try:
        reg = _broker({"op": "register", "assertion": a})
    except Exception as e:
        return json.dumps({"error": f"credential broker unreachable: {type(e).__name__}: {str(e)[:120]}"})
    sid = reg.get("session")
    if not sid:
        return json.dumps({"error": f"broker register failed: {reg.get('error', 'no session')}"})

    cfg = tempfile.mkdtemp(prefix="azcfg-"); t0 = time.time()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": cfg, "LANG": os.environ.get("LANG", "C.UTF-8"),
           "AZURE_TENANT_ID": TENANT, "AZURE_SUBSCRIPTION_ID": DEFAULT_SUB,
           "AZURE_CONFIG_DIR": cfg, "AZURE_EXTENSION_DIR": os.path.join(cfg, "ext"),
           "AZURE_CORE_DISABLE_DYNAMIC_INSTALL": "yes", "AZURE_CORE_COLLECT_TELEMETRY": "no",
           "AZOBO_BROKER_SOCKET": BROKER_SOCKET, "AZOBO_SESSION": sid}
    try:
        with (_sem or _nullctx()):
            so, se, rc, capped, timed_out = _run_capped([VENV_PY, AZOBO] + argv, env, TIMEOUT, MAX_CAPTURE)
        if timed_out:
            out = json.dumps({"error": f"timed out after {TIMEOUT}s — for long ops use --no-wait + poll status"})
        else:
            # Clean contract: on success return stdout only (az writes warnings to
            # stderr even on rc==0); only fold stderr in on failure.
            out = (so if rc == 0 else (so + se)).strip() or "(no output)"
            if capped:
                out += (f"\n\n[…CAPPED: output exceeded {MAX_CAPTURE} bytes and the command was terminated. "
                        "Narrow it with --query / -o tsv / --top, or download to Azure-side storage instead.]")
    finally:
        shutil.rmtree(cfg, ignore_errors=True)
        try: _broker({"op": "end", "session": sid})  # best-effort; broker also TTLs
        except Exception: pass
    return _finalize(owner, who, "az_run", command, out, rc, time.time() - t0)

@mcp.tool()
def read_output(output_id: str, ctx: Context, offset: int = 0, max_chars: int = 0) -> str:
    """Read (more of) a previous command's FULL retained output when az_run truncated it.
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
