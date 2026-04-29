# pass-collector

Super simple Python webserver that accepts GET and POST requests with:

- `client`
- `pass`
- `type`

It stores values in SQLite (`data.db`) and enforces uniqueness on (`client`, `type`).
If the same combination arrives again, the existing value is overwritten.

## Backend modes

`pass-collector` supports two backends:

- `sqlite` (default): local file `data.db` with upsert on (`client`, `type`)
- `vaultwarden`: writes to Vaultwarden HTTP API using delete-then-create with local ID map

Select backend using the config CLI (stored in `data.db`):

```bash
./pass-collector-config config --backend sqlite
```

or:

```bash
./pass-collector-config config --backend vaultwarden
```

### Vaultwarden backend setup

Requirements:

- Vaultwarden API base URL
- API bearer token
- optional organization UUID
- local SQLite `vaultwarden_item_map` table (auto-created in `data.db`) to track cipher IDs per (`client`, `type`)

Example:

```bash
./pass-collector-config config \
	--backend vaultwarden \
	--vw-api-url "https://vaultwarden.example.com" \
	--vw-access-token "..." \
	--vw-organization-id "..."
```

Update behavior in Vaultwarden (no read/search required):

- look up known cipher ID in local SQLite map
- if ID exists: try delete by ID (404 is ignored)
- create new cipher
- save new cipher ID in local SQLite map

Important permission note:

- this mode works without Vaultwarden read/list permissions
- service account still needs create permission and delete permission for its own ciphers
- if records are changed externally, local ID map can drift; next create still succeeds but stale items may remain

### Custom mapping for client/type -> Vaultwarden fields

You can customize how `client` and `type` are mapped into Vaultwarden payloads.

Config keys (stored in SQLite):

- `VW_CLIENT_MAP_JSON`: JSON object remapping client values
- `VW_TYPE_MAP_JSON`: JSON object remapping type values
- `VW_NAME_TEMPLATE`: default `pass-collector:{client}:{type}`
- `VW_USERNAME_TEMPLATE`: default `{client}`
- `VW_NOTES_TEMPLATE`: default `client={client}; type={type}`

Template variables:

- `{client}` and `{type}` are the mapped values
- `{raw_client}` and `{raw_type}` are the original request values

Example:

```bash
./pass-collector-config config \
	--client-map-json '{"acme":"ACME-PROD"}' \
	--type-map-json '{"ssh":"linux-root"}' \
	--name-template 'cred:{client}:{type}' \
	--username-template '{client}' \
	--notes-template 'source=pass-collector; raw={raw_client}/{raw_type}'
```

### Migrate all SQLite entries to Vaultwarden

Use the configuration CLI (not a service endpoint):

```bash
./pass-collector-config migrate \
	--db-path /opt/pass-collector/data.db \
	--vw-api-url "https://vaultwarden.example.com" \
	--vw-access-token "..." \
	--vw-organization-id "..." \
	--client-map-json '{"acme":"ACME-PROD"}' \
	--type-map-json '{"ssh":"linux-root"}' \
	--name-template 'cred:{client}:{type}' \
	--username-template '{client}' \
	--notes-template 'source=pass-collector; raw={raw_client}/{raw_type}'
```

The command prints a JSON summary with total, migrated, failed, and per-entry failures.

Show current stored configuration:

```bash
./pass-collector-config config --show
```

### Bootstrap service user with admin token

Use [pass-collector-config](pass-collector-config) to invite/create a service user without saving the admin token.

Interactive mode is available when running with minimal arguments:

```bash
./pass-collector-config service-user
```

It will prompt for base URL, email, optional org role setup, and the admin token.
In guided mode it asks if you want to set org membership now, then tries to list organizations for you to pick from.
If organization lookup is unavailable, it falls back to asking for org UUID.

Example:

```bash
./pass-collector-config service-user \
	--base-url "https://vaultwarden.example.com" \
	--email "pass-collector@your-domain.local"
```

Optional: if the user is already in an organization, set org role:

```bash
./pass-collector-config service-user \
	--base-url "https://vaultwarden.example.com" \
	--email "pass-collector@your-domain.local" \
	--org-uuid "<org-uuid>" \
	--org-role 2
```

Role values: `0=Owner`, `1=Admin`, `2=User`, `3=Manager`.

Notes:

- Admin token is used only in memory for `/admin` login and is not stored.
- Admin token can invite/create users, but organization membership is separate.
- If user is not already in the target organization, role update will fail and you must invite/add them to org first.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Server starts at `http://localhost:8000`.

## Example requests

Create or update using GET:

```bash
curl "http://localhost:8000/?client=acme&pass=abc123&type=ssh"
```

Update same (`client`, `type`) with new value:

```bash
curl "http://localhost:8000/?client=acme&pass=new-secret&type=ssh"
```

Create or update using POST form data:

```bash
curl -X POST "http://localhost:8000/" \
	-d "client=acme" \
	-d "pass=newest-secret" \
	-d "type=ssh"
```

Create or update using POST JSON:

```bash
curl -X POST "http://localhost:8000/" \
	-H "Content-Type: application/json" \
	-d '{"client":"acme","pass":"json-secret","type":"ssh"}'
```

## Notes

- Query strings are usually logged by proxies and browsers, so GET with secrets is not secure for production.
- Prefer POST for sending secrets.
- This is intentionally minimal for local/simple usage.

## Deploy on RHEL9 (systemd + nginx)

Default install layout:

- `/opt/pass-collector/app.py`
- `/opt/pass-collector/.venv/`

### 1) Install systemd service

```bash
sudo useradd --system --home /opt/pass-collector --shell /sbin/nologin passcollector
sudo cp /opt/pass-collector/pass-collector.service /etc/systemd/system/pass-collector.service
sudo chown -R passcollector:passcollector /opt/pass-collector
sudo systemctl daemon-reload
sudo systemctl enable --now pass-collector
sudo systemctl status pass-collector
```

### 2) Mount behind nginx at /pass-collector/

The provided file is a **location snippet**, not a standalone server block.
Do **not** place it in `/etc/nginx/conf.d/` — that directory is auto-loaded
at the `http {}` level where `location` directives are invalid.

Instead:

```bash
# Copy to the snippets directory (not auto-loaded)
sudo cp /opt/pass-collector/pass-collector.nginx.conf /etc/nginx/snippets/pass-collector.nginx.conf
```

Then add this line **inside** the `server {}` block of your existing HTTPS nginx config:

```nginx
include /etc/nginx/snippets/pass-collector.nginx.conf;
```

Validate and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```