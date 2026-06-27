# azobo — per-user OBO Azure CLI + Microsoft Graph, as an MCP server

`azobo` lets an AI agent run the **full Azure CLI** and **Microsoft Graph** **as the
signed-in user**, over an MCP endpoint, using OAuth 2.0 **On-Behalf-Of (OBO)**. No
shared service-principal god-mode: every call carries the *user's own* identity and is
bounded by *their own* Azure RBAC.

Two generic passthrough tools (no curated/typed wrappers — the model uses its native
`az` fluency):

- **`az_run(command)`** — raw Azure CLI (management plane **and** `az ad` directory).
- **`graph_run(path, method, body)`** — raw Microsoft Graph REST.

## Why this is NOT a giant gaping security hole

The question to answer before deploying, so let's be explicit:

1. **It acts as the user, not as a privileged robot.** Each request carries a per-user
   OAuth token; `azobo` exchanges it (OBO) for a downstream Azure/Graph token **for that
   same user**. Every call is the user — logged as them in Entra sign-in + Azure
   activity logs (real attribution, not an anonymous service principal).
2. **It can't do anything the user can't already do.** Access = the user's own Azure
   RBAC + Entra role. A Contributor scoped to one resource group is blocked everywhere
   else (`AuthorizationFailed`/403) **by Azure**, not by trusting the agent. The tool
   cannot escalate anyone.
3. **The certificate is a broker, not a key to the kingdom.** The confidential-client
   cert can only *exchange a user's valid token* for a downstream token. With no user
   assertion it mints nothing — it is not standing access to Azure.
4. **No shared standing credential.** The dangerous pattern — one over-privileged
   service principal everyone shares — is exactly what OBO avoids: no shared identity to
   over-permission, no lost attribution.
5. **Two-layer model.** The app's consented API permissions are a *ceiling* on which
   audiences are reachable *at all*; each user's RBAC is the *floor* on what they can do.
   Effective access = **ceiling ∩ the user's own roles**.

What you still must protect (honest threat model):

- **The cert** (the OBO broker): if stolen, an attacker still needs a *valid user token*
  to exchange — but protect it like any confidential-client key (file perms, ideally
  HSM/Key Vault). On an Azure host, prefer a **federated Managed Identity** and no cert.
- **In-flight user tokens**: TLS the endpoint; they're short-lived bearer creds.
- **Writes are real.** `az group delete`, `az ad app create`, role assignments mutate
  the tenant as the user. Gate writes behind confirmation/step-up, not blanket auto-run.

## Architecture

```
agent / MCP client ──(user OAuth bearer)──▶ azobo MCP server ──(OBO + cert)──▶ Entra ID
     (token aud = resource app)                    │                              │
                                                    ▼                              ▼
                                       az / Microsoft Graph as the user ◀── downstream token
```

The server holds no per-user secret: the incoming bearer *is* the OBO assertion; the
exchange + cert load happen per call, in an isolated `AZURE_CONFIG_DIR`.

## Prerequisites

- Linux host, Python 3.11+, and (for TLS) nginx.
- A Microsoft Entra tenant where you can create app registrations + grant admin consent.

## Setup

### 1. App registrations (one-time, in Entra)

**Resource app** — what `azobo` authenticates as (the OBO "server"):

1. Entra → **App registrations → New**. Single tenant.
2. **Expose an API** → accept the default **Application ID URI** `api://<client-id>` →
   **Add a scope** `user_impersonation` (who can consent: Admins and users).
3. **Certificates & secrets → Certificates → Upload** the public cert (step 2 below).
4. **API permissions** → add the **delegated** downstream permissions you want reachable
   (each is a *resource* the OBO can mint a token for), then **Grant admin consent**:
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
# Upload obo.crt to the resource app (1.3). Keep obo.key on the host, chmod 600,
# readable by the service user. Thumbprint (no colons) for azobo.env:
openssl x509 -in obo.crt -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
```

### 3. Install

```bash
python3 -m venv /opt/azobo/venv
/opt/azobo/venv/bin/pip install -r requirements.txt
install -m 755 server.py azobo /opt/azobo/
```

### 4. Configure

```bash
sudo install -d /etc/azobo
sudo cp azobo.env.example /etc/azobo/azobo.env   # fill in the values
sudo chmod 600 /etc/azobo/azobo.env
```

### 5. Run

```bash
sudo cp deploy/azobo-mcp.service /etc/systemd/system/
sudo systemctl enable --now azobo-mcp                 # listens on 127.0.0.1:8782
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
- **`az ad` works** (directory), as do `graph_run` and `az rest --resource <r> --url <u>`.
- **Data plane** (blob contents, Key Vault secret values) needs BOTH the API permission
  (1.4) AND the *user's own* data-plane role (Storage Blob Data Reader, KV Secrets User)
  — management roles / Global Admin do **not** grant data access. Use `--auth-mode login`.
- `AuthorizationFailed` / 403 / empty outside a user's scope is **expected** — their RBAC
  boundary, not a bug, and not something to route around.

## How it works (the trick)

Azure CLI can't be handed a raw token via `az login`. `azobo` is a ~40-line wrapper that
monkeypatches `azure-cli`'s `Profile` to inject an OBO token instead of using the local
MSAL account cache — three methods: `get_login_credentials` (ARM, honors
`--subscription`), `load_cached_subscriptions` (live subscription list), and
`get_raw_token` (what `az ad` / `az rest` use). The result: the model writes ordinary
`az` (and `az ad`) commands and they run as the user. See `azobo` and `server.py`.

## License

The latest GPL i guess.
