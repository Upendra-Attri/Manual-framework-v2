# Manual Framework Burp Extension Guide

This guide explains how the Jython extension works and how to use it with the
Manual Framework notebook. The extension is an evidence-import and organization
tool: it reads messages already captured by Burp and sends saved records to the
local Manual Framework API. It does not send or replay requests to target
systems.

## How the pieces fit together

The extension connects to three local components:

1. **Burp Suite** captures traffic during your authorized testing.
2. **The extension** imports a selected Burp request/response, lets you choose
   its framework context, and submits saved records.
3. **The local API** validates and stores the records in the same SQLite
   database used by the Streamlit notebook.

The API listens on `127.0.0.1:8001` by default. The extension only accepts
loopback API URLs (`127.0.0.1`, `localhost`, or `::1`) and authenticates API
calls with a bearer token. The Streamlit interface is where programs, domains,
accounts, objects, and functions are created and associated; the extension
loads those existing records for selection.

## Requirements and installation

- Burp Suite with the legacy Extender API.
- A Jython 2.7-compatible standalone JAR configured in Burp's Python
  environment.
- The Manual Framework V2 project and its Python dependencies.

In Burp, configure the Jython standalone JAR under **Extensions → Extensions
settings → Python environment**. Under **Extensions → Installed**, add
`manual_framework.py` as a Python extension. If loading succeeds, Burp adds a
**Manual Framework** tab. The implementation uses the legacy Extender API; it
is not a Montoya extension.

## Start the local notebook and API

From the `manual-framework_v2` directory, set a random API token of at least 32
characters and start both services:

```bash
export MANUAL_FRAMEWORK_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
python3 run_local.py
```

Keep this terminal running. Paste the same token into the extension's **Bearer
token** field. Enter the token itself, without the `Bearer ` prefix—the
extension adds that prefix to API requests. Use `http://127.0.0.1:8001` as the
API URL unless you intentionally configured another local API port.

The token must be set in the same shell that starts `run_local.py`. If the
application is already running and you did not save the token elsewhere, stop
it with Ctrl+C, generate/export a token, and restart it. Do not publish or share
the token.

## Prepare the framework records

Before connecting Burp, create the records you want to attach evidence to in
Streamlit:

1. Under **Programs & Domains**, create a program.
2. Add the in-scope domain to that program.
3. Under **Accounts**, create any testing accounts.
4. Edit the domain and select the accounts associated with it.
5. If useful, create objects and functions and link them to the appropriate
   account/object.

The Program, Domain, Account / role, Object, and Function selectors in Burp
show saved records; they do not create them from a request's `Host` header. If
a selector only offers `None`, create the corresponding record in Streamlit,
then use **Refresh records** in Burp.

## Connect and load records

1. Open the **Manual Framework** tab.
2. Enter the API URL and token.
3. Click **Connect**.
4. Watch the status text near the bottom of the tab. It should change to
   **Connecting to local API...**, followed by **Connected; requests are never
   sent by this extension**.
5. Use **Refresh records** after creating or changing notebook records.

On connect, the extension calls the local API to load request definitions,
domains, programs, accounts, objects, functions, and test categories. A
connection error is displayed in the status text. The API's `/health` check is
unauthenticated, but all data endpoints require the configured bearer token.
After connecting, the **Auto-record matching Repeater responses** option is
enabled by default.

## Import an already captured Burp message

1. In a Burp tool such as Proxy history or Logger, select a message that has a
   request and (if available) its response.
2. Open the context menu and choose **Import request/response to Manual
   Framework**.
3. The request and response appear in the editors. Importing only copies the
   already-captured message into the extension; it does not save it to the
   notebook yet.
4. Choose a Program, Domain, Account / role, Object, and Function as
   appropriate. These selectors provide context for the evidence and request
   definition.

Selecting a saved request definition fills the context selectors from that
definition when its linked records are available.

## Save a request definition and an evidence attempt

A **request definition** is the saved baseline/checklist record. An **attempt**
is a separate captured test with its own sent request, response, categories,
diff, and annotations.

### Automatic capture from Repeater

After connecting, each completed exchange in Burp Repeater is checked against
the loaded request definitions. The extension only handles Repeater responses;
it does not send or replay the request. A matching response is submitted as a
new attempt in a background thread, so it does not block Burp's UI.

Matching requires:

- The HTTP method to match.
- The Repeater host to match the request definition's linked domain. For
  definitions without a linked domain, the saved request's `Host` header must
  match.
- The route path to match. Query strings are ignored, and numeric or UUID path
  segments are treated as variable IDs (for example, `/users/14` can match
  `/users/29`).

If several definitions match equally well, or none matches, the extension
skips automatic recording instead of guessing. The status text reports that
there was no unique match. Link definitions to the correct domain and avoid
duplicate method/path definitions when you want deterministic auto-matching.
Use **Refresh records** after adding or changing definitions.

### Custom matching

To match modified methods, paths, headers, or bodies without relying on the
default route rules:

1. Select the request definition that should receive the attempts.
2. Set **Repeater matching** to **Custom pattern**.
3. Choose **Literal string** or **Regular expression** in **Pattern type**.
4. Enter a pattern in **Match in request**.
5. Select the applicable entries under **Test categories**.
6. Keep **Auto-record matching Repeater responses** enabled and send the
   Repeater request.

The custom pattern is checked against the complete raw HTTP request (request
line, headers, and body), case-insensitively. A literal pattern matches if it
appears anywhere. A regex uses Python/Jython regular-expression syntax and
matches if it finds a match anywhere; for example,
`(?s)POST /api/items/.*` can match a changed method/path and a multi-line
request body.
The pattern is limited to 512 characters. Avoid complex expressions with
ambiguous nested repetitions, as those can take a long time to evaluate.

Custom mode always assigns a match to the one currently selected request
definition; it does not try to find a definition by route. If no definition is
selected or the pattern is empty, the extension skips the exchange. Switch
back to **Method + host + path** to restore the default matcher. The selected
mode and pattern are session settings and must be re-entered after reloading
the extension.

The **Auto-record matching Repeater responses** checkbox can disable this
behavior. When enabled, every matching completed Repeater exchange creates an
attempt; repeated sends are separate attempts.

To create a request definition:

1. Import or enter a request in the request editor.
2. Select any relevant context.
3. Click **Create request definition**.
4. The extension saves the request through the API and refreshes its records.

To save evidence:

1. Select the request definition that the capture belongs to. Create one first
   if the Request definition selector is empty.
2. Review the request and response editors and select any test categories.
3. Optionally fill in Expected behavior, Observed behavior, and notes.
4. Click **Record captured evidence**.
5. A successful save reports an attempt number; **Refresh history** lists
   attempts for the selected request definition.

When automatic Repeater capture is enabled, matching exchanges are already
saved as attempts; you do not need to click **Record captured evidence** for
those Repeater responses. That button remains available for messages imported
through the context menu or evidence edited in the extension.

Automatic attempts inherit categories from the selected request definition's
checked testing checklist (for example, `idor` or `sqli`), matching checklist
names to the framework's test categories. Any additional categories currently
selected in Burp's **Test categories** list are added as well. Select or change
Burp categories before sending; changing either selection does not edit
attempts that were already saved.

The recorded diff compares the selected request definition's baseline against
the request currently in the editor. The extension does not automatically
replace or modify the baseline when recording an attempt.

## Redaction and stored evidence

By default, the extension:

- Masks common `Authorization`, `Cookie`, and `Set-Cookie` headers and some
  token/password values when displaying imported text.
- Redacts common secrets in request text, response headers, notes, and
  annotations before sending them.
- Omits the response body from the API submission.

These defaults also apply to automatic Repeater attempts. Enabling **Store
unredacted request and response evidence** opts into sending the raw request,
response headers, and response body for both manual and automatic captures.
Responses larger than the API's 10 MiB body limit are saved without the body,
with a note indicating why it was omitted.

Redaction is pattern-based and is not a guarantee that every secret or personal
identifier is removed. Review the data before saving it.

**Display unredacted imported messages** controls whether the editors show the
original imported text or its redacted display. **Store unredacted request and
response evidence** is a separate opt-in for sending raw request/response
evidence to the local API. For imported messages, enabling raw storage requires
enabling unredacted display first. The raw-storage option also includes the
response body; without it, the response body is omitted.

Treat captured evidence and the local database as sensitive. The extension's
unsynced retry queue is stored in Burp's local extension settings, so queued
records may remain on the workstation until successfully retried.

## History, retry, and findings

- **Refresh history** loads attempts for the selected request definition.
- If evidence cannot be submitted, the extension queues the payload locally
  with an idempotency key and reports the error. **Retry unsynced** retries
  queued submissions; successful retries are removed from the queue.
- **Create suspected finding** creates a finding linked to the selected
  request's recorded attempts. It requires at least one attempt and creates the
  finding as *suspected*. Review and update it in Streamlit.

## Troubleshooting

### The extension is loaded, but its tab is missing

Remove the currently loaded copy, then reload the `manual_framework.py` in this
folder. Confirm the extension is configured as **Python** and Burp has a
compatible Jython standalone JAR. Check the extension's **Errors** output for
initialization failures.

### Clicking Connect appears to do nothing

Check the status text in the tab. The current version displays
**Connecting to local API...** while it loads records, followed by either a
success or failure message. If no status changes, first make sure Burp loaded
the updated extension file, then check the extension's **Errors** output.

### Connection failed or the selectors are empty

- Confirm `run_local.py` is still running and Uvicorn reports that it is
  listening on `127.0.0.1:8001` (or the port configured in the extension URL).
- Confirm the token in Burp exactly matches the token exported in the shell
  that started the API. Do not type `Bearer ` into the token field.
- If the status says **Connected** but a selector only has `None`, create the
  record in Streamlit and click **Refresh records**.
- If Connect reports `401`, the bearer token is missing or does not match. A
  `503` indicates the API process does not have a configured token of at least
  32 characters.
- If the status remains at “Connecting...”, check that the local API is
  reachable and inspect Burp's **Errors** output.

### A Repeater response was not automatically recorded

Confirm you clicked **Connect** and **Auto-record matching Repeater responses**
is enabled. In the default mode, the response must match a request definition
by method, host, and path; unmatched or ambiguous messages are skipped and
reported in the status. In custom mode, select the destination request
definition and verify the pattern matches the complete Repeater request. Click
**Refresh records** after changing definitions, then send the Repeater request
again. Check the status for the attempt number or a message that the evidence
was queued for retry.

For a message imported through the context menu, importing alone is not
saving. Select or create a request definition, then click **Record captured
evidence**.

## What the extension does not do

- It does not send, replay, or modify target requests.
- It does not create program/domain/account records from traffic.
- It does not automatically save context-menu imports; use **Record captured
  evidence** for those.
- It does not guarantee that pattern-based redaction removes all sensitive
  content.
