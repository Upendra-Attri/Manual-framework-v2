# Manual Framework Notebook

A local Streamlit notebook and authenticated loopback API for organizing authorized assessment scope, accounts, objects, request definitions, captured test history, and findings. The app records evidence; it does not send target requests.

## Run the application

From this directory, install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Generate a random local API token (at least 32 characters), then export it in the shell used to start the application:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
export MANUAL_FRAMEWORK_API_TOKEN='paste-the-generated-token-here'
python3 run_local.py
```

Streamlit opens on its usual local address. The API listens only on `127.0.0.1:8001` by default. Set `MANUAL_FRAMEWORK_API_PORT` to use another local port. The API requires the bearer token for every endpoint except `/api/v1/health`; it does not enable permissive CORS or log access headers. Do not bind it to a LAN interface.

The SQLite database is `manual_frameworks.db` in this directory. Back it up securely; existing account passwords in older databases are plaintext. API responses omit the password field, and the Streamlit interface masks it.

To run only one service:

```bash
python3 -m streamlit run main.py
python3 api_server.py
```

The API command also requires `MANUAL_FRAMEWORK_API_TOKEN`.

## Burp Suite Jython extension

`burp_extension/manual_framework.py` uses Burp's legacy Jython Extender API. See the [Burp extension guide](burp_extension/README.md) for installation, setup, workflow, evidence handling, and troubleshooting.

Enter the local API URL and token and connect. By default, matching completed Repeater exchanges are automatically recorded as attempts against existing request definitions; the tab also offers custom literal-string or regex matching against the selected definition. Automatic attempts inherit the checked testing checklist from the matching request definition, and may include additional categories selected in Burp. A checkbox can disable automatic capture. The extension does not send requests. Unredacted evidence and response-body storage are opt-in; by default the extension redacts common secret headers and omits the body. Failed API submissions are queued in Burp's local extension settings for explicit retry. See the [Burp extension guide](burp_extension/README.md) for matching and setup details.

## Pages

- **Recon Phases** — preserve phase answers and notes, including optional checklist questions from the adjacent `canava` folder.
- **Programs & Domains** — create target programs, applications/domains, scope notes, policy URLs, and account associations.
- **Accounts** — manage accounts and nested objects; objects cannot be parented under themselves, descendants, or another account's objects.
- **Add Function / View/Edit Functions** — manage functions and their many-to-many object links, request definitions, and checklist classes.
- **Requests & Test History** — inspect captured attempts, filter by category/review state, and update annotations without changing captured evidence.
- **Findings** — explicitly create and review suspected or confirmed findings with linked attempt IDs.
- **Mind Map** — explore program → domain → account → object → function → request → attempt → finding relationships. Filters cover domains, account/role, categories, review status, findings, and node search. Legacy/unlinked records remain visible.
- **Add Class Column** — preserve custom request checklist columns.

## API

All routes use the `/api/v1` prefix and JSON. Include `Authorization: Bearer <token>` on every route except `GET /api/v1/health`.

```text
GET    /api/v1/health
GET    /api/v1/programs
POST   /api/v1/programs
GET    /api/v1/programs/{program_id}
PATCH  /api/v1/programs/{program_id}
DELETE /api/v1/programs/{program_id}
GET/POST /api/v1/domains
GET/PATCH/DELETE /api/v1/domains/{domain_id}
GET/POST /api/v1/accounts
GET/PATCH/DELETE /api/v1/accounts/{account_id}
GET/POST /api/v1/objects
GET/PATCH/DELETE /api/v1/objects/{object_id}
GET/POST /api/v1/functions
GET/PATCH/DELETE /api/v1/functions/{function_id}
GET/POST /api/v1/requests
GET/PATCH/DELETE /api/v1/requests/{request_id}
GET/POST /api/v1/requests/{request_id}/attempts
GET /api/v1/attempts
GET/PATCH /api/v1/attempts/{attempt_id}
GET/POST /api/v1/test-categories
DELETE /api/v1/test-categories/{category_id}
PUT/DELETE /api/v1/attempts/{attempt_id}/categories/{category_id}
GET/POST /api/v1/findings
GET/PATCH/DELETE /api/v1/findings/{finding_id}
GET /api/v1/mind-map
GET /api/v1/recon-phases
GET /api/v1/recon-phases/{phase_name}
PUT/DELETE /api/v1/recon-phases/{phase_name}/answers
PUT/DELETE /api/v1/recon-phases/{phase_name}/notes
```

Lists are paginated with `limit`, `offset`, and optional `search`. Attempt creation accepts response bodies as base64 (maximum 10 MiB) and supports the `Idempotency-Key` header. Attempt annotations are mutable; captured request/response evidence is not. Deleting programs/domains/accounts/functions/requests/findings archives them; deleting objects archives their descendants. The API has no endpoint for sending HTTP requests or executing commands.

## Database migration

Startup initializes missing V1 tables and applies the V2 schema additions without dropping existing rows or columns. `schema_migrations` records the schema version. V2 adds programs, domains, account/domain associations, request context columns, test categories, immutable request attempts, and findings. Before running against an existing database, make a protected backup. The existing `testing_space`, checklist fields, function/object links, and unlinked requests are retained.

## Project files

- `main.py` — Streamlit entry point.
- `api.py`, `api_server.py` — local authenticated API and server entry point.
- `run_local.py` — starts Streamlit and the API together.
- `modules/db.py` — SQLite schema, migration, and persistence functions.
- `modules/gui_functions.py` — pages, forms, and interactive mind map.
- `burp_extension/manual_framework.py` — Jython extension for Repeater evidence capture and manual imports.
- `burp_extension/README.md` — Burp extension setup, behavior, and troubleshooting guide.
- `map.md` — application/data-flow map.
- `map_v2_spec.md` — source V2 specification.
- `timer.py` — separate terminal timer utility.
