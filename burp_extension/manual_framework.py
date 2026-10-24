# Jython 2.7 Burp Extender extension.
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, ITab
from java.awt import BorderLayout, FlowLayout, GridLayout
from java.awt.event import ActionListener
from java.lang import Runnable
from java.util import ArrayList
from javax.swing import (
    BorderFactory,
    JButton,
    JCheckBox,
    JComboBox,
    JLabel,
    JList,
    JOptionPane,
    JPanel,
    JPasswordField,
    JScrollPane,
    JSplitPane,
    JTextArea,
    JTextField,
    ListSelectionModel,
    JMenuItem,
    SwingUtilities,
)
from javax.swing.event import DocumentListener
from javax.swing.event import ListSelectionListener
import base64
import difflib
import json
import re
import threading
import urllib2
import uuid
from urlparse import urlsplit


def _request_route_signature(value):
    lines = value.splitlines()
    if not lines:
        return None
    match = re.match(r"^(\S+)\s+(\S+)\s+HTTP/\S+", lines[0])
    if not match:
        return None
    parsed = urlsplit(match.group(2))
    path = parsed.path or "/"
    path = re.sub(
        r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])",
        "{id}",
        path,
    )
    path = re.sub(r"(?<!\d)\d+(?!\d)", "{id}", path)
    return match.group(1).upper(), path


def _header_host(value):
    match = re.search(r"(?im)^Host:\s*([^\s]+)", value)
    if not match:
        return None
    return match.group(1).strip().lower().rstrip(".")


def _domain_matches_host(domain, host):
    for value in (domain.get("base_url"), domain.get("name")):
        if not value:
            continue
        parsed = urlsplit(value if "://" in value else "//" + value)
        expected = (parsed.hostname or "").lower().rstrip(".")
        if not expected:
            continue
        if expected.startswith("*."):
            suffix = expected[1:]
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == expected:
            return True
    return False


def _enabled_checklist_value(value):
    if isinstance(value, basestring):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _byte_array_to_text(value):
    raw = "".join(chr((int(byte) + 256) % 256) for byte in value)
    return raw.decode("latin-1")


def _text_to_bytes(value):
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError("Raw HTTP evidence contains characters outside the byte range.")


def _redact(value):
    value = re.sub(
        r"(?im)^(authorization|proxy-authorization|cookie|set-cookie):.*$",
        r"\1: [REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)([?&](?:token|access_token|api_key|password|secret)=)[^&\s]+",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(
        r"""(?i)(["']?(?:password|passwd|secret|api[-_]?key|access_token|refresh_token)["']?\s*[:=]\s*["']?)[^"'\s,}]+""",
        r"\1[REDACTED]",
        value,
    )
    return value


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _Runnable(Runnable):
    def __init__(self, callback):
        self.callback = callback

    def run(self):
        self.callback()


class _DocumentChange(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def changedUpdate(self, event):
        self.callback()

    def insertUpdate(self, event):
        self.callback()

    def removeUpdate(self, event):
        self.callback()


class _ListSelectionChange(ListSelectionListener):
    def __init__(self, callback):
        self.callback = callback

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.callback()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Manual Framework")
        self.requests = []
        self.domains = []
        self.category_data = []
        self.requests_loaded = False
        self.auto_capture_enabled = True
        self.store_raw_evidence = False
        self.selected_category_ids = []
        self.matching_mode_value = "Method + host + path"
        self.match_pattern_type_value = "Literal string"
        self.match_pattern_value = ""
        self.selected_request_id = None
        self.queue_lock = threading.RLock()
        self._build_ui()
        self.unsynced = []
        saved_attempts = callbacks.loadExtensionSetting("unsynced_attempts")
        if saved_attempts:
            try:
                self.unsynced = json.loads(saved_attempts)
            except ValueError as error:
                callbacks.printError(
                    "Could not load locally queued attempts: %s" % error
                )
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.printOutput("Manual Framework Jython extension loaded.")

    def getTabCaption(self):
        return "Manual Framework"

    def getUiComponent(self):
        return self.root

    def _build_ui(self):
        self.root = JPanel(BorderLayout(8, 8))
        self.root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        connection = JPanel(GridLayout(4, 1, 4, 4))
        connection_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.api_url = JTextField("http://127.0.0.1:8001", 28)
        self.api_token = JPasswordField(28)
        self.connect_button = JButton("Connect")
        self.connect_button.addActionListener(_Action(self._connect))
        connection_row.add(JLabel("API URL"))
        connection_row.add(self.api_url)
        connection_row.add(JLabel("Bearer token"))
        connection_row.add(self.api_token)
        connection_row.add(self.connect_button)
        request_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.request_combo = JComboBox()
        self.request_combo.setPrototypeDisplayValue("Request #000000 - long baseline preview")
        self.refresh_button = JButton("Refresh records")
        self.refresh_button.addActionListener(_Action(self._connect))
        self.create_request_button = JButton("Create request definition")
        self.create_request_button.addActionListener(_Action(self._create_request))
        request_row.add(JLabel("Request definition"))
        request_row.add(self.request_combo)
        request_row.add(self.refresh_button)
        request_row.add(self.create_request_button)
        context_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.program_combo = JComboBox()
        self.domain_combo = JComboBox()
        self.account_combo = JComboBox()
        self.object_combo = JComboBox()
        self.function_combo = JComboBox()
        context_row.add(JLabel("Program"))
        context_row.add(self.program_combo)
        context_row.add(JLabel("Domain"))
        context_row.add(self.domain_combo)
        context_row.add(JLabel("Account / role"))
        context_row.add(self.account_combo)
        context_row.add(JLabel("Object"))
        context_row.add(self.object_combo)
        context_row.add(JLabel("Function"))
        context_row.add(self.function_combo)
        matching_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.matching_mode = JComboBox()
        self.matching_mode.addItem("Method + host + path")
        self.matching_mode.addItem("Custom pattern")
        self.match_pattern_type = JComboBox()
        self.match_pattern_type.addItem("Literal string")
        self.match_pattern_type.addItem("Regular expression")
        self.match_pattern = JTextField(32)
        self.matching_mode.addActionListener(
            _Action(self._update_matching_setting)
        )
        self.match_pattern_type.addActionListener(
            _Action(self._update_matching_setting)
        )
        self.match_pattern.getDocument().addDocumentListener(
            _DocumentChange(self._update_matching_setting)
        )
        matching_row.add(JLabel("Repeater matching"))
        matching_row.add(self.matching_mode)
        matching_row.add(JLabel("Pattern type"))
        matching_row.add(self.match_pattern_type)
        matching_row.add(JLabel("Match in request"))
        matching_row.add(self.match_pattern)
        connection.add(connection_row)
        connection.add(request_row)
        connection.add(context_row)
        connection.add(matching_row)
        self.request_combo.addActionListener(
            _Action(self._selected_request_changed)
        )

        self.request_editor = JTextArea(18, 80)
        self.response_editor = JTextArea(18, 80)
        self.response_editor.setEditable(True)
        self.request_editor.setLineWrap(False)
        self.response_editor.setLineWrap(False)
        editors = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            JScrollPane(self.request_editor),
            JScrollPane(self.response_editor),
        )
        editors.setResizeWeight(0.5)

        lower = JPanel(BorderLayout(6, 6))
        self.categories = JList()
        self.categories.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.categories.setVisibleRowCount(4)
        self.categories.addListSelectionListener(
            _ListSelectionChange(self._update_selected_categories)
        )
        lower.add(JLabel("Test categories"), BorderLayout.NORTH)
        lower.add(JScrollPane(self.categories), BorderLayout.WEST)
        annotation = JPanel(GridLayout(5, 1, 4, 4))
        self.expected = JTextField()
        self.observed = JTextField()
        self.notes = JTextArea(4, 50)
        annotation.add(self._labeled("Expected behavior", self.expected))
        annotation.add(self._labeled("Observed behavior", self.observed))
        annotation.add(JScrollPane(self.notes))
        self.keep_raw = JCheckBox("Store unredacted request and response evidence", False)
        self.show_unredacted = JCheckBox(
            "Display unredacted imported messages", False
        )
        self.show_unredacted.addActionListener(
            _Action(self._toggle_raw_display)
        )
        self.keep_raw.addActionListener(
            _Action(self._update_raw_storage_setting)
        )
        self.auto_capture = JCheckBox(
            "Auto-record matching Repeater responses (method, host, path)",
            True,
        )
        self.auto_capture.addActionListener(
            _Action(self._update_auto_capture_setting)
        )
        record_controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.record_button = JButton("Record captured evidence")
        self.record_button.addActionListener(_Action(self._record))
        self.history_button = JButton("Refresh history")
        self.history_button.addActionListener(_Action(self._refresh_history))
        self.retry_button = JButton("Retry unsynced")
        self.retry_button.addActionListener(_Action(self._retry_unsynced))
        self.finding_button = JButton("Create suspected finding")
        self.finding_button.addActionListener(_Action(self._create_finding))
        self.status = JLabel("Not connected")
        record_controls.add(self.keep_raw)
        record_controls.add(self.show_unredacted)
        record_controls.add(self.auto_capture)
        record_controls.add(self.record_button)
        record_controls.add(self.history_button)
        record_controls.add(self.retry_button)
        record_controls.add(self.finding_button)
        record_controls.add(self.status)
        annotation.add(record_controls)
        self.history = JTextArea(5, 60)
        self.history.setEditable(False)
        annotation.add(JScrollPane(self.history))
        lower.add(annotation, BorderLayout.CENTER)

        self.root.add(connection, BorderLayout.NORTH)
        self.root.add(editors, BorderLayout.CENTER)
        self.root.add(lower, BorderLayout.SOUTH)

    def _labeled(self, label, component):
        panel = JPanel(BorderLayout(4, 2))
        panel.add(JLabel(label), BorderLayout.NORTH)
        panel.add(component, BorderLayout.CENTER)
        return panel

    def _base_url(self):
        value = self.api_url.getText().strip().rstrip("/")
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or parsed.username
            or parsed.password
        ):
            raise ValueError("API URL must use localhost or a loopback address")
        return value

    def _token(self):
        return "".join(self.api_token.getPassword())

    def _api(self, method, path, payload=None, idempotency_key=None):
        url = self._base_url() + path
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib2.Request(url, data=data)
        request.get_method = lambda: method
        request.add_header("Authorization", "Bearer " + self._token())
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if idempotency_key:
            request.add_header("Idempotency-Key", idempotency_key)
        response = urllib2.urlopen(request, timeout=5)
        content = response.read()
        return json.loads(content) if content else None

    def _fill_combo(self, combo, items, labeler):
        combo.removeAllItems()
        combo.addItem("None")
        for item in items:
            combo.addItem(labeler(item))

    def _selected_id(self, combo, items):
        index = combo.getSelectedIndex()
        if index <= 0 or index > len(items):
            return None
        item = items[index - 1]
        for key in ("id", "program_id", "domain_id", "object_id", "function_id"):
            if key in item:
                return item[key]
        return None

    def _connect(self):
        if getattr(self, "connecting", False):
            return
        self.connecting = True
        self.connect_button.setEnabled(False)
        self.status.setText("Connecting to local API...")
        worker = threading.Thread(target=self._load_records)
        worker.setDaemon(True)
        worker.start()

    def _load_records(self):
        try:
            self._api("GET", "/api/v1/health")
            request_data = self._api("GET", "/api/v1/requests?limit=500")
            domain_data = self._api("GET", "/api/v1/domains?limit=200")
            program_data = self._api("GET", "/api/v1/programs?limit=200")
            account_data = self._api("GET", "/api/v1/accounts?limit=200")
            object_data = self._api("GET", "/api/v1/objects?limit=500")
            function_data = self._api("GET", "/api/v1/functions?limit=500")
            categories = self._api("GET", "/api/v1/test-categories")
            data = (
                request_data,
                domain_data,
                program_data,
                account_data,
                object_data,
                function_data,
                categories,
            )
            SwingUtilities.invokeLater(
                _Runnable(lambda: self._connection_succeeded(data))
            )
        except Exception as error:
            message = str(error)
            SwingUtilities.invokeLater(
                _Runnable(lambda: self._connection_failed(message))
            )

    def _update_auto_capture_setting(self):
        self.auto_capture_enabled = self.auto_capture.isSelected()
        if self.auto_capture_enabled:
            self.status.setText("Automatic Repeater evidence capture enabled")
        else:
            self.status.setText("Automatic Repeater evidence capture disabled")

    def _update_raw_storage_setting(self):
        self.store_raw_evidence = self.keep_raw.isSelected()

    def _update_selected_categories(self):
        self.selected_category_ids = [
            self.category_data[index]["category_id"]
            for index in self.categories.getSelectedIndices()
            if index < len(self.category_data)
        ]

    def _definition_category_ids(self, definition):
        request_fields = {
            re.sub(r"[^a-z0-9]", "", key.lower()): value
            for key, value in definition.items()
            if isinstance(key, basestring)
        }
        category_ids = []
        for category in self.category_data:
            category_key = re.sub(
                r"[^a-z0-9]", "", category["name"].lower()
            )
            if _enabled_checklist_value(request_fields.get(category_key)):
                category_ids.append(category["category_id"])
        return category_ids

    def _update_matching_setting(self):
        self.matching_mode_value = str(self.matching_mode.getSelectedItem())
        self.match_pattern_type_value = str(
            self.match_pattern_type.getSelectedItem()
        )
        self.match_pattern_value = self.match_pattern.getText()

    def _connection_succeeded(self, data):
        (
            request_data,
            domain_data,
            program_data,
            account_data,
            object_data,
            function_data,
            categories,
        ) = data
        self.requests = request_data["items"]
        self.programs = program_data["items"]
        self.domains = domain_data["items"]
        self.accounts = account_data["items"]
        self.objects = object_data["items"]
        self.functions = function_data["items"]
        self.category_data = categories
        for request in self.requests:
            request["test_category_ids"] = self._definition_category_ids(request)
        self.requests_loaded = True
        self._fill_combo(
            self.program_combo,
            self.programs,
            lambda item: "%s (#%s)" % (item["name"], item["program_id"]),
        )
        self._fill_combo(
            self.domain_combo,
            self.domains,
            lambda item: "%s (#%s)" % (item["name"], item["domain_id"]),
        )
        self._fill_combo(
            self.account_combo,
            self.accounts,
            lambda item: "%s (%s)" % (item["account_name"], item.get("role") or "role not set"),
        )
        self._fill_combo(
            self.object_combo,
            self.objects,
            lambda item: "%s (#%s)" % (item["object_name"], item["object_id"]),
        )
        self._fill_combo(
            self.function_combo,
            self.functions,
            lambda item: "%s (#%s)" % (item["function_name"], item["function_id"]),
        )
        selected_request_id = self.selected_request_id
        self.request_combo.removeAllItems()
        for item in self.requests:
            preview = " ".join((item.get("request") or "").split())[:50]
            self.request_combo.addItem("Request #%s - %s" % (item["id"], preview))
        restored = False
        if selected_request_id is not None:
            for index, item in enumerate(self.requests):
                if item["id"] == selected_request_id:
                    self.request_combo.setSelectedIndex(index)
                    restored = True
                    break
        if not restored and self.requests:
            self.request_combo.setSelectedIndex(0)
        selected_index = self.request_combo.getSelectedIndex()
        self.selected_request_id = (
            self.requests[selected_index]["id"]
            if 0 <= selected_index < len(self.requests)
            else None
        )
        self.categories.setListData([item["name"] for item in self.category_data])
        self._update_selected_categories()
        self.connecting = False
        self.connect_button.setEnabled(True)
        self.status.setText(
            "Connected; matching Repeater responses are recorded automatically"
            if self.auto_capture_enabled
            else "Connected; automatic Repeater capture is disabled"
        )

    def _connection_failed(self, message):
        self.connecting = False
        self.requests_loaded = False
        self.connect_button.setEnabled(True)
        self.status.setText("Connection failed: %s" % message)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if (
            toolFlag != self.callbacks.TOOL_REPEATER
            or messageIsRequest
        ):
            return
        if not self.auto_capture_enabled:
            return
        if not self.requests_loaded:
            SwingUtilities.invokeLater(
                _Runnable(lambda: self.status.setText(
                    "Connect to the API before auto-recording Repeater responses"
                ))
            )
            return
        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()
        if not request_bytes or not response_bytes:
            return
        try:
            request_text = _byte_array_to_text(request_bytes)
            response_text = _byte_array_to_text(response_bytes)
            service = messageInfo.getHttpService()
            host = str(service.getHost()).lower().rstrip(".") if service else None
            definition = self._match_request_definition(request_text, host)
            if definition is None:
                lines = request_text.splitlines()
                route = lines[0] if lines else "unknown request"
                message = "No unique request definition matched Repeater: %s" % route
                SwingUtilities.invokeLater(
                    _Runnable(lambda: self.status.setText(message))
                )
                return
            payload, idempotency_key = self._build_repeater_attempt(
                definition, request_text, response_text
            )
        except Exception as error:
            message = "Automatic matching failed: %s" % error
            SwingUtilities.invokeLater(
                _Runnable(lambda: self.status.setText(message))
            )
            self.callbacks.printError(
                message
            )
            return
        worker = threading.Thread(
            target=self._submit_repeater_attempt,
            args=(definition["id"], payload, idempotency_key),
        )
        worker.setDaemon(True)
        worker.start()

    def _match_request_definition(self, captured_request, host):
        if self.matching_mode_value == "Custom pattern":
            definition = next(
                (
                    item
                    for item in self.requests
                    if item["id"] == self.selected_request_id
                ),
                None,
            )
            pattern = self.match_pattern_value
            if definition is None or not pattern:
                return None
            if len(pattern) > 512:
                raise ValueError("custom pattern must be 512 characters or fewer")
            if self.match_pattern_type_value == "Regular expression":
                return (
                    definition
                    if re.search(pattern, captured_request, re.IGNORECASE | re.MULTILINE)
                    else None
                )
            return (
                definition
                if pattern.lower() in captured_request.lower()
                else None
            )
        captured_signature = _request_route_signature(captured_request)
        if captured_signature is None or not host:
            return None
        captured_method, captured_path = captured_signature
        captured_path_exact = urlsplit(
            captured_request.splitlines()[0].split()[1]
        ).path or "/"
        captured_host_header = _header_host(captured_request)
        domains_by_id = {
            item["domain_id"]: item for item in getattr(self, "domains", [])
        }
        matches = []
        for item in self.requests:
            baseline = item.get("request") or ""
            baseline_signature = _request_route_signature(baseline)
            if baseline_signature is None or baseline_signature[0] != captured_method:
                continue
            baseline_exact_path = urlsplit(
                baseline.splitlines()[0].split()[1]
            ).path or "/"
            if baseline_signature[1] != captured_path:
                continue
            domain_id = item.get("domain_id")
            domain = domains_by_id.get(domain_id)
            if domain is not None:
                if not _domain_matches_host(domain, host):
                    continue
            elif _header_host(baseline) != (captured_host_header or host):
                continue
            matches.append(
                (
                    0 if baseline_exact_path == captured_path_exact else 1,
                    item,
                )
            )
        if not matches:
            return None
        best_score = min(item[0] for item in matches)
        best_matches = [item[1] for item in matches if item[0] == best_score]
        return best_matches[0] if len(best_matches) == 1 else None

    def _build_repeater_attempt(self, definition, request_text, response_text):
        raw_storage = self.store_raw_evidence
        response_status, response_headers, response_body = self._response_fields(
            response_text
        )
        baseline = definition.get("request") or ""
        diff_lines = list(
            difflib.unified_diff(
                baseline.splitlines(),
                request_text.splitlines(),
                fromfile="baseline",
                tofile="repeater",
                lineterm="",
            )
        )
        notes = "Automatically recorded from Burp Repeater."
        include_body = raw_storage and len(response_body) <= 10 * 1024 * 1024
        if raw_storage and response_body and not include_body:
            notes += " Response body omitted because it exceeds the API 10 MiB limit."
        payload = {
            "request_id": definition["id"],
            "account_id": definition.get("account_id"),
            "sent_request": (
                request_text if raw_storage else _redact(request_text)
            ),
            "baseline_request": (
                baseline if raw_storage else _redact(baseline)
            ),
            "test_category_ids": sorted(
                set(definition.get("test_category_ids", []))
                | set(self.selected_category_ids)
            ),
            "response_status": response_status,
            "response_headers": (
                response_headers if raw_storage else _redact(response_headers)
            ),
            "response_body_base64": (
                base64.b64encode(response_body) if include_body else None
            ),
            "response_body_encoding": "binary",
            "diff": {"unified": _redact("\n".join(diff_lines))},
            "notes": notes,
            "expected_behavior": "",
            "observed_behavior": "",
        }
        return payload, str(uuid.uuid4())

    def _submit_repeater_attempt(self, request_id, payload, idempotency_key):
        try:
            attempt = self._api(
                "POST",
                "/api/v1/requests/%s/attempts" % request_id,
                payload,
                idempotency_key,
            )
            message = "Auto-recorded Repeater attempt #%s" % attempt["attempt_id"]
        except Exception as error:
            message = self._queue_failed_attempt(
                request_id, payload, idempotency_key, error
            )
        SwingUtilities.invokeLater(
            _Runnable(lambda: self.status.setText(message))
        )

    def _queue_failed_attempt(self, request_id, payload, idempotency_key, error):
        item = {
            "path": "/api/v1/requests/%s/attempts" % request_id,
            "payload": payload,
            "idempotency_key": idempotency_key,
        }
        with self.queue_lock:
            self.unsynced.append(item)
            try:
                self.callbacks.saveExtensionSetting(
                    "unsynced_attempts", json.dumps(self.unsynced)
                )
                return "Repeater attempt queued for retry: %s" % error
            except Exception as storage_error:
                self.callbacks.printError(
                    "Could not persist queued Repeater evidence: %s" % storage_error
                )
                return "Repeater save failed and local queue could not be persisted: %s" % (
                    storage_error
                )

    def _selected_request(self):
        index = self.request_combo.getSelectedIndex()
        if index < 0 or index >= len(getattr(self, "requests", [])):
            return None
        return self.requests[index]

    def _select_context_id(self, combo, items, key, value):
        combo.setSelectedIndex(0)
        if value is None:
            return
        for index, item in enumerate(items):
            if item.get(key) == value:
                combo.setSelectedIndex(index + 1)
                return

    def _selected_request_changed(self):
        selected = self._selected_request()
        if selected is None:
            self.selected_request_id = None
            return
        self.selected_request_id = selected["id"]
        if hasattr(self, "domains"):
            self._select_context_id(
                self.domain_combo, self.domains, "domain_id", selected.get("domain_id")
            )
            selected_domain_id = selected.get("domain_id")
            selected_domain = next(
                (
                    item
                    for item in self.domains
                    if item["domain_id"] == selected_domain_id
                ),
                None,
            )
            self._select_context_id(
                self.program_combo,
                self.programs,
                "program_id",
                selected_domain.get("program_id") if selected_domain else None,
            )
            self._select_context_id(
                self.account_combo, self.accounts, "id", selected.get("account_id")
            )
            self._select_context_id(
                self.object_combo, self.objects, "object_id", selected.get("object_id")
            )
            self._select_context_id(
                self.function_combo,
                self.functions,
                "function_id",
                selected.get("function_id"),
            )

    def _create_request(self):
        request_text = self.request_editor.getText()
        if not request_text.strip():
            self.status.setText("Import or enter a request first")
            return
        if (
            self.keep_raw.isSelected()
            and hasattr(self, "imported_request")
            and not self.show_unredacted.isSelected()
        ):
            self.status.setText(
                "Enable unredacted display before storing an unredacted baseline"
            )
            return
        domain_id = self._selected_id(self.domain_combo, self.domains)
        program_id = self._selected_id(self.program_combo, self.programs)
        if program_id is not None and domain_id is None:
            self.status.setText("Select a domain in the chosen program")
            return
        if domain_id is not None:
            domain = next(
                item for item in self.domains if item["domain_id"] == domain_id
            )
            if program_id is not None and domain["program_id"] != program_id:
                self.status.setText("The selected domain belongs to another program")
                return
        try:
            baseline_text = (
                request_text
                if self.keep_raw.isSelected()
                else _redact(request_text)
            )
            item = self._api(
                "POST",
                "/api/v1/requests",
                {
                    "request": baseline_text,
                    "testing_space": "",
                    "domain_id": domain_id,
                    "account_id": self._selected_id(
                        self.account_combo, self.accounts
                    ),
                    "object_id": self._selected_id(
                        self.object_combo, self.objects
                    ),
                    "function_id": self._selected_id(
                        self.function_combo, self.functions
                    ),
                },
            )
            self._connect()
            for index, request in enumerate(self.requests):
                if request["id"] == item["id"]:
                    self.request_combo.setSelectedIndex(index)
                    break
            self.status.setText("Created request definition #%s" % item["id"])
        except Exception as error:
            self.status.setText("Could not create definition: %s" % error)

    def _response_fields(self, response):
        raw_response = _text_to_bytes(response)
        split_at = raw_response.find("\r\n\r\n")
        if split_at < 0:
            return None, "", raw_response
        headers = raw_response[:split_at]
        body = raw_response[split_at + 4 :]
        status = None
        match = re.match(r"(?m)^HTTP/\S+\s+(\d{3})", headers)
        if match:
            status = int(match.group(1))
        return status, headers, body

    def _record(self):
        selected = self._selected_request()
        if selected is None:
            self.status.setText("Create or select a request definition first")
            return
        if (
            self.keep_raw.isSelected()
            and hasattr(self, "imported_request")
            and not self.show_unredacted.isSelected()
        ):
            self.status.setText(
                "Enable unredacted display before storing unredacted evidence"
            )
            return
        request_text = self.request_editor.getText()
        response_text = self.response_editor.getText()
        payload = None
        idempotency_key = str(uuid.uuid4())
        try:
            response_status, response_headers, response_body = self._response_fields(
                response_text
            )
            baseline = selected.get("request") or ""
            diff_lines = list(
                difflib.unified_diff(
                    baseline.splitlines(),
                    request_text.splitlines(),
                    fromfile="baseline",
                    tofile="captured",
                    lineterm="",
                )
            )
            categories = [
                self.category_data[index]["category_id"]
                for index in self.categories.getSelectedIndices()
            ]
            payload = {
                "request_id": selected["id"],
                "account_id": self._selected_id(
                    self.account_combo, self.accounts
                ),
                "sent_request": request_text if self.keep_raw.isSelected() else _redact(request_text),
                "baseline_request": baseline if self.keep_raw.isSelected() else _redact(baseline),
                "test_category_ids": categories,
                "response_status": response_status,
                "response_headers": response_headers if self.keep_raw.isSelected() else _redact(response_headers),
                "response_body_base64": (
                    base64.b64encode(response_body)
                    if self.keep_raw.isSelected()
                    else None
                ),
                "response_body_encoding": "binary",
                "diff": {"unified": _redact("\n".join(diff_lines))},
                "notes": _redact(self.notes.getText()),
                "expected_behavior": _redact(self.expected.getText()),
                "observed_behavior": _redact(self.observed.getText()),
            }
            attempt = self._api(
                "POST",
                "/api/v1/requests/%s/attempts" % selected["id"],
                payload,
                idempotency_key,
            )
            self.status.setText(
                "Evidence saved as attempt #%s" % attempt["attempt_id"]
            )
            self._refresh_history()
        except Exception as error:
            if payload is not None:
                message = self._queue_failed_attempt(
                    selected["id"], payload, idempotency_key, error
                )
                self.status.setText(message.replace("Repeater attempt", "Evidence"))

    def _refresh_history(self):
        selected = self._selected_request()
        if selected is None:
            return
        try:
            attempts = self._api(
                "GET", "/api/v1/requests/%s/attempts" % selected["id"]
            )
            lines = []
            for attempt in attempts:
                lines.append(
                    "Attempt #%s | %s | HTTP %s | %s | %s"
                    % (
                        attempt["attempt_id"],
                        attempt.get("categories") or "uncategorized",
                        attempt.get("response_status") or "not captured",
                        attempt["review_status"],
                        _redact(attempt.get("notes") or ""),
                    )
                )
            self.history.setText("\n".join(lines) or "No attempts recorded.")
        except Exception as error:
            self.status.setText("Could not load history: %s" % error)

    def _create_finding(self):
        selected = self._selected_request()
        if selected is None:
            self.status.setText("Select a request definition first")
            return
        title = JOptionPane.showInputDialog(
            self.root, "Finding title (this creates a suspected finding)"
        )
        if title is None or not title.strip():
            return
        try:
            attempts = self._api(
                "GET", "/api/v1/requests/%s/attempts" % selected["id"]
            )
            if not attempts:
                self.status.setText("Record an attempt before creating a finding")
                return
            self._api(
                "POST",
                "/api/v1/findings",
                {
                    "title": title.strip(),
                    "status": "suspected",
                    "attempt_ids": [item["attempt_id"] for item in attempts],
                },
            )
            self.status.setText("Suspected finding created; review it in Streamlit")
        except Exception as error:
            self.status.setText("Could not create finding: %s" % error)

    def _retry_unsynced(self):
        with self.queue_lock:
            pending = list(self.unsynced)
            self.unsynced = []
        if not pending:
            self.status.setText("No unsynced attempts")
            return
        remaining = []
        saved_count = 0
        last_error = None
        for item in pending:
            try:
                self._api(
                    "POST",
                    item["path"],
                    item["payload"],
                    item["idempotency_key"],
                )
                saved_count += 1
            except Exception as error:
                remaining.append(item)
                last_error = error
        with self.queue_lock:
            self.unsynced = remaining + self.unsynced
            queued = list(self.unsynced)
            try:
                self.callbacks.saveExtensionSetting(
                    "unsynced_attempts", json.dumps(queued)
                )
            except Exception as error:
                self.status.setText(
                    "%s attempts saved; could not update retry queue: %s"
                    % (saved_count, error)
                )
                return
        self.status.setText(
            "%s attempts synced; %s remain queued%s"
            % (
                saved_count,
                len(queued),
                " (last error: %s)" % last_error if last_error else "",
            )
        )

    def createMenuItems(self, invocation):
        item = JMenuItem("Import request/response to Manual Framework")
        item.addActionListener(
            _Action(lambda: self._import_selected_messages(invocation))
        )
        menu = ArrayList()
        menu.add(item)
        return menu

    def _import_selected_messages(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            self.status.setText("No selected Burp message")
            return
        message = messages[0]
        request = message.getRequest()
        response = message.getResponse()
        self.imported_request = _byte_array_to_text(request) if request else ""
        self.imported_response = _byte_array_to_text(response) if response else ""
        self._toggle_raw_display()
        self.status.setText(
            "Imported captured message; use Record captured evidence to save it"
        )

    def _toggle_raw_display(self):
        if not hasattr(self, "imported_request"):
            return
        if self.show_unredacted.isSelected():
            self.request_editor.setText(self.imported_request)
            self.response_editor.setText(self.imported_response)
        else:
            self.request_editor.setText(_redact(self.imported_request))
            self.response_editor.setText(_redact(self.imported_response))
