# Manual Bug-Bounty Framework --- Version 2 Specification

**Status:** Proposed specification\
**Baseline:** Existing `map.md` / Streamlit + SQLite framework\
**Goal:** Preserve current functionality while making manual testing
faster through a domain-oriented mind map, a local API, and a Burp Suite
extension.

## 1. Goals and design principles

Version 2 should reduce friction between performing a test and recording
what happened. A tester should be able to select a target context once,
send modified requests, and have the framework preserve the
request/response evidence and testing notes automatically.

Principles:

1.  Preserve existing recon notes, accounts, object hierarchy,
    functions, request checklists, and mind-map exploration.
2.  Treat the database as the source of truth. Streamlit and Burp are
    clients of the same stored data.
3.  Separate reusable request definitions from individual test attempts.
4.  Preserve history: a new attempt must not overwrite an earlier
    attempt or its evidence.
5.  Make relationships flexible. Parents may have multiple children;
    functions can relate to multiple objects; requests and test attempts
    can have multiple test categories.
6.  Keep the initial deployment local and simple, with explicit
    authentication and safe handling of credentials.
7.  Never mark a vulnerability as confirmed solely because of a response
    status, response difference, or automated note.

## 2. Existing functionality to preserve

The current framework documented in `map.md` includes:

-   Streamlit application with sidebar navigation and a local SQLite
    database.
-   Recon Phases with optional questions loaded from
    `canava/manual_recon_and_app_mapping.md`, saved answers, free-form
    notes, phase selection, and deletion of saved answers.
-   Accounts with optional email, username, password, role,
    organization/team, account type, and notes.
-   Nested objects associated with accounts, including editing and safe
    parent changes.
-   Functions that can be linked to multiple objects, including function
    boundaries and notes.
-   Requests associated with functions, testing-space notes, and
    built-in/custom checklist classes.
-   View/Edit Functions for managing function details and associated
    requests.
-   Interactive mind map with pan, zoom, node dragging, layout
    direction, minimap, and record details.
-   Add Class Column for custom request checklist classes.
-   Existing database compatibility behavior and retention of existing
    records where possible.
-   Separate terminal timer utility, `timer.py`, storing elapsed time in
    `bug_hunting_time.json`.

Built-in checklist classes currently include `ssrf`, `idor`, `xss`,
`sqli`, `csrf`, `rce`, `lfi`, and `open_redirect`. Existing spellings
and fields should be migrated carefully rather than silently discarded.

## 3. Proposed hierarchy and relationships

### 3.1 Mind-map hierarchy

The default target map should be:

``` text
PROGRAM
└── Domain / Application
    ├── Account A (role: admin)
    │   ├── Object: Organization
    │   │   ├── Subobject: Project
    │   │   └── Subobject: Member
    │   └── Object: Invoice
    └── Account B (role: member)
        └── Object: Project
            └── Subobject: Settings

Objects → Functions / Operations → Request definitions → Test attempts → Findings
```

This is a conceptual view, not one rigid database tree. A domain can
have many accounts; an account can be associated with many objects; an
object can have many descendants; a function can be linked to multiple
objects; and a request definition can have many test attempts.
Cross-links should be displayed without duplicating the underlying
record.

### 3.2 Entity definitions

-   **Program:** A bounty program or assessment context, including name,
    scope notes, policy/reference URL, and status.
-   **Domain/application:** A host, base URL, API, or application
    boundary under a program. A program can have multiple
    domains/applications.
-   **Account:** A testing identity, including role, team/organization,
    account type, and notes. Prefer a reference to a local credential
    profile or secret store over storing plaintext passwords.
-   **Object:** A resource or entity being tested, such as a workspace,
    user, project, invoice, or API resource. Objects can have nested
    children.
-   **Function/operation:** A behavior or action such as create, read,
    update, delete, invite, export, or change email. It may be linked to
    multiple objects.
-   **Request definition:** A reusable baseline request associated with
    a function and optional object/domain/account context.
-   **Test attempt:** An immutable record of one send operation,
    including the actual request sent, response received, differences
    from the baseline or previous attempt, category, timestamp, and
    notes.
-   **Test category:** A built-in or custom vulnerability/testing class
    such as IDOR or SSRF.
-   **Finding:** A suspected or confirmed issue with evidence, status,
    severity, impact, and report notes.
-   **Recon phase:** Existing reconnaissance checklist/notes, retained
    as a separate workflow.

### 3.3 Relationship rules

-   A program has many domains/applications.
-   A domain/application can have many accounts and request definitions.
-   An account can be associated with multiple objects; object
    ownership/context must be explicit.
-   An account has many objects in the initial compatibility model. If
    shared objects across accounts are required, use an explicit
    many-to-many association rather than duplicating objects.
-   An object may have one parent and many child objects. Reject
    self-parenting and cycles.
-   Functions and objects have a many-to-many relationship.
-   A function has many request definitions.
-   A request definition has many test attempts.
-   A test attempt can have multiple test categories.
-   Findings may reference one or more test attempts and request
    definitions.
-   Deleting a parent must not silently erase historical testing
    evidence. Prefer soft deletion or archival for records with history.

## 4. Mind-map behavior

The updated map should:

1.  Show Program → Domain/Application → Account → Object → nested
    subobjects as the primary hierarchy.
2.  Show Function/Operation, Request, Test Attempt, and Finding as
    connected branches or cross-links.
3.  Support multiple siblings under every applicable parent.
4.  Display IDs, names, roles, status, and short notes on selection.
5.  Keep the existing direction controls, drag, pan, zoom, minimap, and
    details panel.
6.  Provide filters for domain, account/role, object, function, test
    category, testing status, and findings.
7.  Distinguish untested, tested, needs-review, and finding states
    without implying that testing is complete just because a category
    was selected.
8.  Keep orphaned legacy records visible in a clearly labeled
    legacy/unlinked group until the user links or archives them.
9.  Avoid making the graph unreadable: collapse branches, search nodes,
    and expand on demand.
10. Update the graph when relationships change, without losing unrelated
    layout state where feasible.

## 5. API architecture

### 5.1 Important implementation constraint

The chosen direction is an API integrated into the existing Streamlit
application package. Streamlit is primarily a UI framework and is not
designed to act as a general-purpose REST API router. Therefore,
implement the API in the same repository and share the same
database/service layer, but run a small local API server alongside
Streamlit (for example, FastAPI on loopback). This preserves a single
local product and shared data without relying on unsupported Streamlit
internals.

Suggested local development launch command may start both services
through one launcher. Bind the API to `127.0.0.1` by default, not all
network interfaces. Use a configurable port and a local API token. The
API must not be exposed to a LAN or the internet by default.

### 5.2 API conventions

-   Prefix routes with `/api/v1`.
-   Use JSON request and response bodies.
-   Use stable IDs, not display names, for relationships.
-   Validate required fields and relationship ownership server-side.
-   Return useful HTTP status codes and structured error messages.
-   Add pagination and search to list endpoints.
-   Support request idempotency for test-attempt creation where
    practical, to avoid duplicate entries on retry.
-   Add schema/version information and a health endpoint.
-   Keep database writes in a shared service/repository layer used by
    both Streamlit and the API.
-   Do not accept arbitrary filesystem paths or execute commands through
    the API.

### 5.3 Proposed endpoints

  ----------------------------------------------------------------------------------------------------------
  Method                  Endpoint                                                   Purpose
  ----------------------- ---------------------------------------------------------- -----------------------
  GET                     `/api/v1/health`                                           Health and schema
                                                                                     version

  GET/POST                `/api/v1/programs`                                         List/create programs

  GET/PATCH/DELETE        `/api/v1/programs/{program_id}`                            Read/update/archive a
                                                                                     program

  GET/POST                `/api/v1/domains`                                          List/create
                                                                                     domains/applications

  GET/PATCH/DELETE        `/api/v1/domains/{domain_id}`                              Read/update/archive a
                                                                                     domain

  GET/POST                `/api/v1/accounts`                                         List/create accounts

  GET/PATCH/DELETE        `/api/v1/accounts/{account_id}`                            Read/update/archive an
                                                                                     account

  GET/POST                `/api/v1/objects`                                          List/create objects

  GET/PATCH/DELETE        `/api/v1/objects/{object_id}`                              Read/update/archive an
                                                                                     object

  GET/POST                `/api/v1/functions`                                        List/create functions

  GET/PATCH/DELETE        `/api/v1/functions/{function_id}`                          Read/update/archive a
                                                                                     function

  GET/POST                `/api/v1/requests`                                         List/create request
                                                                                     definitions

  GET/PATCH/DELETE        `/api/v1/requests/{request_id}`                            Read/update/archive a
                                                                                     request definition

  GET                     `/api/v1/requests/{request_id}/attempts`                   List test attempts for
                                                                                     a request

  POST                    `/api/v1/requests/{request_id}/attempts`                   Create an immutable
                                                                                     test-attempt record

  GET                     `/api/v1/attempts/{attempt_id}`                            Read attempt details
                                                                                     and evidence

  PATCH                   `/api/v1/attempts/{attempt_id}`                            Update only mutable
                                                                                     annotation fields, not
                                                                                     captured evidence

  GET/POST                `/api/v1/test-categories`                                  List/create custom
                                                                                     categories

  PUT/DELETE              `/api/v1/attempts/{attempt_id}/categories/{category_id}`   Link/unlink a category

  GET/POST                `/api/v1/findings`                                         List/create findings

  GET/PATCH               `/api/v1/findings/{finding_id}`                            Read/update finding
                                                                                     status and report
                                                                                     fields

  GET                     `/api/v1/mind-map`                                         Return nodes, edges,
                                                                                     filters, and display
                                                                                     metadata

  GET/POST/PATCH/DELETE   `/api/v1/recon-phases...`                                  Preserve current recon
                                                                                     phase and answer
                                                                                     functionality
  ----------------------------------------------------------------------------------------------------------

For destructive operations, prefer archive/soft-delete where records
have linked test history. If hard deletion is supported, show the
consequences and protect referential integrity.

### 5.4 Example test-attempt payload

``` json
{
  "request_id": "req_123",
  "account_id": "acct_2",
  "test_categories": ["idor"],
  "baseline_request": "GET /api/users/104/profile HTTP/1.1",
  "sent_request": "GET /api/users/105/profile HTTP/1.1",
  "response_status": 403,
  "response_headers": "...",
  "response_body": "...",
  "diff": {
    "path": {"before": "/api/users/104/profile", "after": "/api/users/105/profile"}
  },
  "notes": "Changed the user identifier to compare authorization behavior."
}
```

This is illustrative. In the implementation, use a consistent encoding
for raw HTTP messages, support binary bodies, and avoid duplicating
large bodies in multiple tables. Evidence may be stored as related
blobs/files with metadata and retention limits.

## 6. Burp Suite extension specification

### 6.1 Main custom workspace

The extension should add a dedicated Burp Suite tab/workspace with:

-   Framework connection status and target-context selector.
-   Program/domain, account/role, object, function, request definition,
    and test-category selectors.
-   Request editor and response viewer.
-   Send button and in-progress/error state.
-   Baseline-versus-current request diff.
-   Test-attempt history for the selected request.
-   Notes and finding actions.
-   A control to redact secrets in displayed notes/diffs.
-   A link/action to open the related record in the Streamlit UI where
    practical.

The extension should use the supported Burp extension API (such as
Montoya API for Java-based extensions) and remain compatible with a
documented range of Burp versions.

### 6.2 Native Repeater import

Provide a context-menu action such as **Send to Manual Framework** for a
request selected in Repeater or other supported Burp request views. The
action should import the request into the custom workspace, then let the
user select or confirm its function, object, account, and category.

Do not assume the extension can observe every later edit and Send action
in native Repeater. Native Repeater import is a convenience path; the
custom workspace is the reliable path for automatic test history. If a
supported API later provides an appropriate event, it can be added
behind a capability check.

### 6.3 Send and record lifecycle

For every send from the custom workspace:

1.  Validate that the target is in the tester's authorized scope; show
    the destination clearly.
2.  Capture the exact request that will be sent.
3.  Send using Burp's supported HTTP functionality so configured Burp
    networking behavior is respected.
4.  Capture the actual response, including status, headers, and body
    where available.
5.  Compare the sent request with the selected baseline or previous
    attempt.
6.  Create an immutable test-attempt record through the API.
7.  Attach one or more selected categories and the current
    function/request context.
8.  Display a success/error result and the saved attempt ID.
9.  If the API is unavailable, retain the unsaved attempt locally for
    retry and clearly mark it as unsynced. Never silently discard it.

The extension should not send requests merely because a request editor
changed. Sending must be an explicit user action. This avoids accidental
traffic and incomplete evidence.

### 6.4 Change detection

The diff should identify changes to:

-   HTTP method, path, query parameters, and HTTP version where
    relevant.
-   Headers, cookies, and authorization values.
-   JSON, form-urlencoded, multipart, XML, and plain-text bodies.
-   Raw bytes when a structured parser is unsuitable.

Show both a readable semantic diff and access to the exact raw request.
Redact or mask secrets in rendered notes by default, while retaining raw
evidence only when the user has opted into that behavior and local
storage is protected. Record whether a diff is against the original
baseline or the previous attempt.

### 6.5 Category-wise test notes

Each attempt belongs to one request definition and can be associated
with multiple categories. The UI should group history by category, for
example:

``` text
SSRF
  Attempt 1 — changed URL parameter → response summary
  Attempt 2 — changed URL parameter → response summary

IDOR
  Attempt 1 — changed object identifier → response summary
```

Allow free-form notes, expected behavior, observed behavior, and a
review state. Do not automatically convert a category test into a
vulnerability finding. A user must explicitly create or confirm a
finding.

## 7. Database changes and migration

Retain existing tables and data where feasible. Add new tables and
relationships through versioned, transactional migrations.

Likely additions:

-   `programs`
-   `domains` or `applications`
-   `account_domains` if accounts need explicit domain associations
-   `request_attempts`
-   `attempt_categories`
-   `findings`
-   `finding_attempts`
-   `api_tokens` or a simple local-token configuration mechanism
-   Optional `evidence_blobs` metadata table if large request/response
    bodies are stored separately
-   A schema migration/version table

Existing `accounts`, `objects`, `functions`, `function_objects`,
`requests`, `recon_phase_answers`, and `recon_phase_notes` should be
migrated without losing records. Existing `requests.testing_space` and
checklist fields should be retained or mapped to the new notes/category
model, not discarded.

Migration plan:

1.  Back up `manual_frameworks.db`.
2.  Record the current schema version and inspect existing rows.
3.  Create new tables and columns without dropping old ones.
4.  Migrate old checklist values and function/object associations.
5.  Keep old requests without function associations visible as
    legacy/unlinked records.
6.  Verify row counts, foreign-key integrity, and key relationships.
7.  Only remove obsolete columns in a later migration after a tested
    backup and explicit compatibility decision.

## 8. Security and reliability

-   Bind the API to loopback by default and require a random local token
    for extension calls.
-   Restrict CORS to the actual local UI origin where applicable; do not
    use permissive wildcard settings with credentials.
-   Validate IDs and ownership/relationship consistency for every write.
-   Never log passwords, session cookies, authorization headers, or API
    tokens.
-   Mask secrets in notes, diffs, and UI previews by default.
-   Protect database backups and any raw HTTP evidence because they may
    contain live session data or personal information.
-   Provide configurable evidence retention and a clear delete/export
    path.
-   Use transactions for related writes and maintain foreign-key
    integrity.
-   Surface API failures, failed sends, and unsynced records explicitly.
-   Avoid automatic repeated sends, unbounded concurrency, or
    destructive test behavior.
-   Keep testing within program scope and the user's authorization.

## 9. Existing pages and proposed navigation

Keep the current pages and add new ones only where useful:

-   **Recon Phases:** preserve current behavior.
-   **Programs & Domains:** new target and application organization.
-   **Accounts:** preserve and extend current identity management.
-   **Objects:** preserve nested object management; consider moving it
    to its own page if the Accounts page becomes crowded.
-   **Functions:** preserve multi-object links and boundaries.
-   **Requests & Test History:** show request definitions and immutable
    attempts.
-   **Findings:** new issue tracking and report-preparation workflow.
-   **Mind Map:** new domain-first view with filters and expandable
    branches.
-   **Add Class Column / Test Categories:** preserve custom checklist
    support while introducing normalized category records.
-   **Settings / API Status:** local API health, port, connection token
    setup, data backup, and schema version.

The terminal timer utility remains separate unless a later version
explicitly integrates it.

## 10. Suggested implementation phases

### Phase 1 --- Stabilize and document the data model

-   Back up the current database.
-   Define IDs and relationships for program, domain, account, object,
    function, request, attempt, category, and finding.
-   Write migration tests against a copy of a real existing database.

### Phase 2 --- Database and shared service layer

-   Implement versioned migrations.
-   Move business rules into shared database/service functions used by
    Streamlit and the API.
-   Preserve current pages and behaviors.

### Phase 3 --- Local API

-   Implement `/api/v1` endpoints, validation, token authentication,
    pagination, error handling, and health checks.
-   Add API tests for CRUD operations and relationship integrity.

### Phase 4 --- Mind map v2

-   Implement the domain-first hierarchy, cross-links, filters, search,
    expand/collapse, and legacy record visibility.
-   Verify the map against multiple accounts, domains, objects, and
    functions.

### Phase 5 --- Burp extension MVP

-   Implement the custom tab, request/response editors, explicit Send,
    category selection, baseline diff, and API persistence.
-   Add native Repeater context-menu import.
-   Test connection loss and retry behavior.

### Phase 6 --- Test history and findings

-   Add category-wise attempt history, annotations, evidence management,
    and explicit finding creation.
-   Add report-ready summaries only after evidence is reviewed.

### Phase 7 --- Hardening and release

-   Test migration rollback/backup restoration, secret redaction, API
    authentication, and data integrity.
-   Document installation, compatibility, troubleshooting, and
    backup/restore.
-   Keep a clear release checklist and change log.

## 11. Acceptance criteria

Version 2 is ready when:

-   All current recon phases, answers, accounts, nested objects,
    functions, requests, checklist classes, and mind-map controls still
    work.
-   A program can have multiple domains; a domain can have multiple
    accounts; parents can have multiple child objects at arbitrary
    depth.
-   A function can link to multiple objects without duplicate records.
-   A request definition can retain many test attempts without
    overwriting earlier attempts.
-   Each attempt stores the sent request, response, timestamp, category
    associations, and a readable diff.
-   The extension can import a request from a supported native Repeater
    context into its custom workspace.
-   Sending from the custom workspace saves the attempt through the API
    and displays its persisted ID.
-   An API outage does not silently lose a captured attempt.
-   Existing database records survive migration and legacy/unlinked
    records remain discoverable.
-   The API is loopback-only by default, authenticated, and does not
    expose credentials in logs.
-   The mind map reflects relationship changes and does not falsely
    imply a vulnerability is confirmed.

## 12. Open decisions before implementation

Resolve these during design, before locking the schema:

1.  Can a single account be linked to multiple domains, and can the same
    object be shared across accounts?
2.  Should raw request/response evidence be stored indefinitely, or
    should the user configure retention?
3.  Should test categories be attached only to attempts, or also to the
    reusable request definition as planned test coverage?
4.  Should findings be a lightweight tracker or include full report
    templates and export?
5.  Which Burp versions and operating systems must be supported?
6.  Should credentials be stored in the framework at all, or should
    account entries store labels and rely on Burp/session handling?

## 13. Recommended default decisions

For a practical first release:

-   Keep the app local and SQLite-backed.
-   Use a small local API server in the same repository and shared
    service layer, launched with the Streamlit UI.
-   Use the custom Burp workspace as the primary send-and-record
    workflow.
-   Support native Repeater import without promising interception of
    every native Repeater edit/send.
-   Keep request definitions immutable enough to preserve a baseline,
    and store every send as a separate test attempt.
-   Support multiple categories per attempt and require explicit user
    confirmation before creating a finding.
-   Preserve old tables/data through migrations and keep a database
    backup before every schema upgrade.
