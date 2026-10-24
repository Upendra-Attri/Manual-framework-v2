# Manual Framework — Application Map

## Runtime

```text
run_local.py
├── Streamlit UI (main.py → modules/gui_functions.py)
└── FastAPI local API (api_server.py → api.py)
    └── modules/db.py
        └── manual_frameworks.db (SQLite)

Burp Suite Jython extension
└── imports captured request/response messages and records them through /api/v1
```

The API binds to loopback and requires `MANUAL_FRAMEWORK_API_TOKEN` on every data route. Health reports API/schema versions. The API records data; it has no target-request sender. Burp's custom tab imports messages selected in Burp and submits captured evidence only when the user presses **Record captured evidence**.

## Data model

```text
PROGRAM
└── programs
    └── domains
        ├── account_domains ── accounts
        │                       └── objects ── child objects
        │                            └── function_objects ── functions
        │                                                      └── requests
        │                                                          └── request_attempts
        │                                                               ├── attempt_categories ── test_categories
        │                                                               └── finding_attempts ── findings
        └── requests (optional domain/account context)

recon_phase_answers / recon_phase_notes remain an independent workflow.
```

## Storage and compatibility

`modules/db.py:init_db()` retains the existing V1 accounts, object hierarchy, functions, many-to-many function links, requests, checklists, and recon data. It adds missing request context columns and creates V2 tables inside the initialization transaction. `schema_migrations` records schema version 2. Legacy request rows without a function/domain association are not deleted and appear under the map's **Legacy / Unlinked** group.

`request_attempts` stores request snapshots, sent request, optional response evidence, response status/headers, diff JSON, review annotations, and a creation timestamp. Attempt annotations can be updated, but captured request/response fields are not editable through the API. A unique idempotency key can prevent duplicates on a retry. Categories are many-to-many with attempts. Findings are separate records and are created only by an explicit user action.

Program/domain/account/finding archival retains linked history. Account passwords from the legacy schema remain local SQLite plaintext for compatibility; the Streamlit view masks them and the API excludes them.

## User workflows

1. **Recon Phases** retains phase notes and answers.
2. **Programs & Domains** records target scope and account-to-domain associations.
3. **Accounts** manages identities and account-owned nested objects.
4. **Functions** links operations to multiple objects and stores baseline request definitions.
5. **Burp extension** imports a selected request/response, then records evidence via the authenticated local API. Sending remains an explicit native Burp action and is not performed by the extension.
6. **Requests & Test History** reviews attempts by category and annotates them without changing captured evidence.
7. **Findings** tracks suspected/confirmed issues and their supporting attempts.
8. **Mind Map** renders relationships and supports layout, node search, relationship/category/status filters, pan, zoom, minimap, and selected-record details.

## API surface

`api.py` exposes authenticated `/api/v1` routes for programs, domains, accounts, objects, functions, request definitions, attempts, categories, findings, mind-map data, and recon phase reads. Lists use `limit`, `offset`, and `search`. Relationship IDs are validated by the database/service layer; raw response bytes are base64-encoded in JSON. No arbitrary filesystem paths or command execution are accepted.
