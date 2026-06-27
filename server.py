import os, re, shlex, shutil, subprocess, tempfile, json, time, uuid, base64, threading
import urllib.request, urllib.error, msal
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

PUBLIC_HOST = os.environ.get("AZOBO_PUBLIC_HOST", "localhost")
TENANT = os.environ["AZOBO_TENANT_ID"]; CLIENT = os.environ["AZOBO_CLIENT_ID"]
THUMB = os.environ["AZOBO_CERT_THUMBPRINT"]
KEY = os.environ["AZOBO_CERT_KEY"]; CERT = os.environ["AZOBO_CERT_PUB"]
DEFAULT_SUB = os.environ.get("AZOBO_DEFAULT_SUBSCRIPTION", "")
VENV_PY = os.environ.get("AZOBO_PYTHON", "/opt/azobo/venv/bin/python")
AZOBO = os.environ.get("AZOBO_WRAPPER", "/opt/azobo/azobo")
TIMEOUT = int(os.environ.get("AZOBO_TIMEOUT", "150"))
MAX_OUT = int(os.environ.get("AZOBO_MAX_OUTPUT_CHARS", "100000"))  # ~25k tokens; full output is always saved
OUT_DIR = os.environ.get("AZOBO_OUTPUT_DIR", "/opt/azobo/output")
AUDIT = os.environ.get("AZOBO_AUDIT_LOG", "/opt/azobo/audit.log")
os.makedirs(OUT_DIR, exist_ok=True)
_lock = threading.Lock()

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

def _who(b):
    try:
        p = b.split('.')[1]; p += '=' * (-len(p) % 4); c = json.loads(base64.urlsafe_b64decode(p))
        return c.get("upn") or c.get("preferred_username") or c.get("oid") or "?"
    except Exception:
        return "?"

def _audit(who, tool, cmd, rc, dur, n, oid):
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "who": who,
                      "tool": tool, "cmd": cmd[:500], "rc": rc, "dur": round(dur, 2),
                      "out_chars": n, "output_id": oid})
    try:
        with _lock, open(AUDIT, "a") as f:
            f.write(rec + "\n")
    except Exception:
        pass

def _finalize(who, tool, cmd, out, rc, dur):
    """Save full output (owner-stamped), prune, audit, and return a capped view."""
    oid = uuid.uuid4().hex[:12]
    try:
        with open(os.path.join(OUT_DIR, oid + ".txt"), "w") as f:
            f.write(who + "\n" + out)
        files = sorted((os.path.join(OUT_DIR, x) for x in os.listdir(OUT_DIR)), key=os.path.getmtime, reverse=True)
        for old in files[300:]:
            try: os.remove(old)
            except Exception: pass
    except Exception:
        pass
    _audit(who, tool, cmd, rc, dur, len(out), oid)
    if len(out) <= MAX_OUT:
        return out
    return out[:MAX_OUT] + (f"\n\n[…TRUNCATED: returned {MAX_OUT} of {len(out)} chars. Full output "
        f"saved as output_id='{oid}'. Read the rest with read_output(output_id='{oid}', offset={MAX_OUT}), "
        f"or re-run with a narrower --query / -o tsv / --top.]")

@mcp.tool()
def az_run(command: str, ctx: Context) -> str:
    """Run a raw Azure CLI command AS YOU (the signed-in user, via on-behalf-of) and return its output.
    Write it as in a terminal but WITHOUT the leading `az` (e.g. `network vnet show -g RG -n NAME -o json`,
    `vm list -o table`, `group list --query "[].name"`, `ad app list`). Full az surface, under YOUR Azure
    RBAC. Directory works too: `ad app/sp/user/group ...`. For any other endpoint/audience use
    `rest --method GET --url <url> --resource <resource>`.
    Rules: ONE command per call (no `&&`/pipes/`--follow`/`--watch`); filter with `--query` (JMESPath) and
    `-o json/table/tsv`. Large output is truncated in the reply but FULLY SAVED — page it with
    read_output(output_id). A 403/AuthorizationFailed/empty result outside your scope is your permission
    boundary, not an error to route around. Writes (create/delete, role/app changes) are real."""
    a = _bearer(ctx)
    if not a:
        return json.dumps({"error": "no bearer token on request"})
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
    cfg = tempfile.mkdtemp(prefix="azcfg-"); t0 = time.time(); rc = -1
    try:
        env = dict(os.environ, AZOBO_ASSERTION=a, AZOBO_CLIENT_ID=CLIENT, AZOBO_KEY=KEY, AZOBO_CERT=CERT,
                   AZOBO_THUMB=THUMB, AZURE_TENANT_ID=TENANT, AZURE_SUBSCRIPTION_ID=DEFAULT_SUB,
                   AZURE_CONFIG_DIR=cfg)
        r = subprocess.run([VENV_PY, AZOBO] + argv, env=env, capture_output=True, text=True, timeout=TIMEOUT)
        rc = r.returncode
        out = (r.stdout if rc == 0 else (r.stdout + r.stderr)).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        out = json.dumps({"error": f"timed out after {TIMEOUT}s — for long ops use --no-wait + poll status"})
    finally:
        shutil.rmtree(cfg, ignore_errors=True)
    return _finalize(_who(a), "az_run", command, out, rc, time.time() - t0)

@mcp.tool()
def graph_run(path: str, ctx: Context, method: str = "GET", body: str = "", allow_write: bool = False) -> str:
    """Call Microsoft Graph AS YOU (per-user OBO) — the directory tool (Entra/AAD apps, service
    principals, users, groups). path e.g. `applications`, `servicePrincipals?$top=10`, `me` (v1.0 assumed).
    method GET (default)/POST/PATCH/DELETE; mutations require allow_write=true; body = JSON string.
    Note: `az ad ...` and `az rest` (via az_run) also reach Graph. Large output is truncated + saved
    (page with read_output)."""
    a = _bearer(ctx)
    if not a:
        return json.dumps({"error": "no bearer token on request"})
    if method.upper() != "GET" and not allow_write:
        return json.dumps({"error": f"{method} is a write — pass allow_write=true to permit"})
    t0 = time.time()
    app = msal.ConfidentialClientApplication(CLIENT, authority=f"https://login.microsoftonline.com/{TENANT}",
        client_credential={"private_key": open(KEY).read(), "thumbprint": THUMB,
                           "public_certificate": open(CERT).read()})
    r = app.acquire_token_on_behalf_of(user_assertion=a, scopes=["https://graph.microsoft.com/.default"])
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
    return _finalize(_who(a), "graph_run", f"{method} {path}", out, rc, time.time() - t0)

@mcp.tool()
def read_output(output_id: str, ctx: Context, offset: int = 0, max_chars: int = 0) -> str:
    """Read (more of) a previous command's FULL saved output when az_run/graph_run truncated it.
    Pass the output_id from the truncation note. offset = start char; max_chars = how many (default = cap).
    Only the user who produced the output can read it."""
    a = _bearer(ctx)
    if not re.fullmatch(r"[0-9a-f]{1,32}", output_id or ""):
        return json.dumps({"error": "bad output_id"})
    fp = os.path.join(OUT_DIR, output_id + ".txt")
    if not os.path.exists(fp):
        return json.dumps({"error": "output_id not found (expired/pruned or wrong id)"})
    raw = open(fp).read(); owner, _, data = raw.partition("\n")
    if owner != _who(a):
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
