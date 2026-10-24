import re
import sqlite3
from pathlib import Path

import streamlit as st
from streamlit_flow import streamlit_flow
from streamlit_flow.elements import StreamlitFlowEdge, StreamlitFlowNode
from streamlit_flow.layouts import LayeredLayout
from streamlit_flow.state import StreamlitFlowState

from modules.db import (
    add_request,
    add_vuln_column,
    archive_domain,
    archive_program,
    create_domain,
    create_program,
    create_test_category,
    delete_account,
    delete_request,
    delete_recon_phase_answers,
    delete_test_category,
    delete_vuln_column,
    get_all_accounts,
    get_all_functions,
    get_all_objects,
    get_all_requests,
    get_domains,
    get_programs,
    get_functions_for_account,
    get_objects_for_account,
    get_object_ids_for_function,
    get_requests_for_function,
    get_request_class_columns,
    get_request_attempts,
    get_all_request_attempts,
    get_test_categories,
    get_findings,
    get_schema_version,
    archive_finding,
    create_finding,
    update_attempt_annotations,
    update_finding,
    get_recon_phase_names,
    init_db,
    load_recon_phase_answers,
    save_account,
    save_function,
    save_object,
    save_recon_phase_answer,
    update_account,
    update_domain,
    update_program,
    update_request,
    update_function,
    update_object,
    update_csrf,
    update_idor,
    update_lfi,
    update_open_redirect,
    update_rce,
    update_ssrf,
    update_sqli,
    update_test_space,
    update_testing_space,
    update_vuln,
    update_xss,
)


def _ensure_db() -> None:
    init_db()


def _normalize_search_value(value) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _filter_by_search(items: list, searchable_fields: list[str], query: str) -> list:
    if not query:
        return items

    query = _normalize_search_value(query)
    if not query:
        return items

    filtered: list = []
    for item in items:
        haystack = " ".join(
            _normalize_search_value(item.get(field, "")) for field in searchable_fields
        )
        if query in haystack:
            filtered.append(item)
    return filtered


def _display_request_details(request: dict) -> None:
    st.markdown(f"### Request #{request.get('id')}")
    st.markdown(f"**Bug type / testing space / notes:**")
    st.code(_redact_secrets(request.get("testing_space") or "—"), language="text")
    st.markdown("**Request:**")
    raw_request = request.get("request", "")
    if st.checkbox("Show unredacted request", key=f"raw_request_{request.get('id')}"):
        st.code(raw_request, language="text")
    else:
        st.code(_redact_secrets(raw_request), language="text")

    threat_fields = []
    for key in sorted(request.keys()):
        if key in {"id", "request", "testing_space", "created_at"}:
            continue
        if isinstance(request.get(key), (int, bool)) and bool(request.get(key)):
            threat_fields.append(key)

    if threat_fields:
        st.markdown("**Threat-modeling / relevant classes:**")
        st.write(", ".join(threat_fields))
    else:
        st.caption("No threat-model classes selected for this request.")


def _redact_secrets(value: str) -> str:
    value = re.sub(
        r"(?im)^(authorization|proxy-authorization|cookie|set-cookie):.*$",
        r"\1: [REDACTED]",
        value,
    )
    value = re.sub(
        r"(?im)^((?:password|passwd|secret|api[-_]?key|token)\s*[:=]\s*).+$",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(
        r"""(?i)(["']?(?:password|passwd|secret|api[-_]?key|access_token|refresh_token)["']?\s*[:=]\s*["']?)[^"'\s,}]+""",
        r"\1[REDACTED]",
        value,
    )
    return re.sub(
        r"(?i)([?&](?:token|access_token|api_key|password|secret)=)[^&\s]+",
        r"\1[REDACTED]",
        value,
    )


def add_request_ui() -> None:
    _ensure_db()
    st.subheader("Add request")

    with st.form("add_request_form", clear_on_submit=True):
        request = st.text_area("Full request", height=180)
        testing_space = st.text_area(
            "Bug type / testing space / notes",
            help="Use this for the bug type, testing notes, findings, and anything else you want to track.",
            height=220,
        )

        class_values = {}
        class_columns = st.columns(3)
        for index, class_name in enumerate(get_request_class_columns()):
            with class_columns[index % 3]:
                class_values[class_name] = st.checkbox(f"Relevant for {class_name}")

        submitted = st.form_submit_button("Save request")

    if submitted:
        if not request.strip():
            st.warning("Please enter a request before saving.")
            return

        request_id = add_request(
            request=request,
            testing_space=testing_space,
            **class_values,
        )
        st.success(f"Request saved with ID: {request_id}")


def all_requests_ui() -> None:
    _ensure_db()
    st.subheader("All requests")

    requests = get_all_requests()
    if not requests:
        st.info("No requests saved yet.")
        return

    search_query = st.sidebar.text_input("Search requests", placeholder="ID, request, class, testing space")
    filtered_requests = _filter_by_search(
        requests,
        ["id", "request", "testing_space", *get_request_class_columns()],
        search_query,
    )

    if not filtered_requests:
        st.warning("No requests match your search.")
        return

    request_ids = [req["id"] for req in filtered_requests]
    selected_id = st.sidebar.selectbox(
        "Request list",
        request_ids,
        format_func=lambda x: f"Request #{x}",
    )

    selected_request = next(req for req in filtered_requests if req["id"] == selected_id)
    _display_request_details(selected_request)

    st.markdown("---")
    st.subheader("Edit selected request")

    threat_columns = [
        key
        for key in sorted(selected_request.keys())
        if key not in {"id", "request", "testing_space", "created_at"}
    ]

    edited_testing_space = st.text_area(
        "Bug type / testing space / notes",
        value=selected_request.get("testing_space") or "",
        height=220,
    )

    cols = st.columns(3)
    for idx, key in enumerate(threat_columns):
        with cols[idx % 3]:
            setattr(
                st,
                "_",
                st.checkbox(
                    f"Relevant for {key}",
                    value=bool(selected_request.get(key)),
                    key=f"req_{selected_id}_{key}",
                ),
            )

    if st.button("Save changes to this request"):
        update_testing_space(selected_id, edited_testing_space)
        for key in threat_columns:
            value = st.session_state.get(f"req_{selected_id}_{key}", False)
            update_vuln(selected_id, key, value)
        st.success(f"Changes saved for Request #{selected_id}")

    if st.button("Delete selected request", type="secondary"):
        delete_request(selected_id)
        st.success(f"Request #{selected_id} deleted")
        st.rerun()


def add_vuln_column_ui() -> None:
    _ensure_db()
    st.subheader("Add new threat-model class column")

    with st.form("add_vuln_column_form"):
        column_name = st.text_input("New class name")
        default_value = st.checkbox("Default this class to 1?", value=False)
        submitted = st.form_submit_button("Add column")

    if submitted:
        if not column_name.strip():
            st.warning("Please enter a class name.")
            return

        try:
            add_vuln_column(column_name, default_value=1 if default_value else 0)
        except (ValueError, sqlite3.IntegrityError) as exc:
            st.error(str(exc))
        else:
            st.success(f"Column '{column_name}' added to the requests table.")
            st.rerun()

    st.markdown("---")
    st.subheader("Request classes")
    for class_name in get_request_class_columns():
        class_col, delete_col = st.columns([5, 1])
        class_col.write(class_name)
        if delete_col.button("Delete", key=f"delete_class_{class_name}"):
            delete_vuln_column(class_name)
            st.rerun()


def _get_recon_questions_from_markdown() -> dict[str, list[str]]:
    md_path = Path(__file__).resolve().parents[2] / "canava" / "manual_recon_and_app_mapping.md"
    if not md_path.exists():
        return {}

    lines = md_path.read_text(encoding="utf-8").splitlines()
    phases: dict[str, list[str]] = {}
    current_phase: str | None = None

    for raw_line in lines:
        line = raw_line.strip()

        if line.startswith("## "):
            current_phase = line[3:].strip()
            if current_phase:
                phases.setdefault(current_phase, [])
            continue

        if current_phase is None:
            continue

        cleaned = line.strip()

        if not cleaned:
            continue

        if cleaned.startswith("- [ ] "):
            item = cleaned[6:].strip()
            if item:
                phases[current_phase].append(item)
            continue

        if cleaned.startswith("- [x] "):
            item = cleaned[7:].strip()
            if item:
                phases[current_phase].append(item)
            continue

        if cleaned.startswith("- **") and cleaned.endswith("**"):
            item = cleaned[4:-2].strip()
            if item:
                phases[current_phase].append(item)
            continue

        if cleaned.startswith("**") and cleaned.endswith("**"):
            item = cleaned[2:-2].strip()
            if item and any(marker in item.lower() for marker in ["what", "who", "where", "which", "why", "how", "when", "can", "should"]) :
                phases[current_phase].append(item)
            continue

        if cleaned.startswith("- ") and "?" in cleaned:
            item = cleaned[2:].strip().rstrip("?") + "?"
            if item:
                phases[current_phase].append(item)

    return phases


def recon_phase_ui() -> None:
    _ensure_db()
    st.subheader("Manual Recon & App Mapping")

    phase_map = _get_recon_questions_from_markdown()
    phases = list(dict.fromkeys([*phase_map.keys(), *get_recon_phase_names()]))
    with st.expander("Add phase"):
        with st.form("add_recon_phase_form", clear_on_submit=True):
            new_phase = st.text_input("Phase name")
            add_phase = st.form_submit_button("Add phase")
        if add_phase:
            if not new_phase.strip():
                st.warning("Please enter a phase name.")
            else:
                save_recon_phase_answer(new_phase, "__freeform__", "")
                st.success(f"Added phase: {new_phase.strip()}")
                st.rerun()

    if not phases:
        st.warning("No recon phases could be loaded from the markdown file.")
        return

    phase_search = st.sidebar.text_input("Search phases", placeholder="Phase name or keyword")
    if phase_search:
        phases = [phase for phase in phases if phase_search.lower() in phase.lower()]

    if not phases:
        st.warning("No phases match your search.")
        return

    phase = st.sidebar.selectbox("Choose a phase", phases)
    questions = phase_map.get(phase, [])
    saved_answers = load_recon_phase_answers(phase)

    st.markdown(f"### {phase}")
    if not questions:
        st.info("No checklist questions were extracted from this phase in the markdown file. You can add notes below.")
        freeform_notes = st.text_area(
            "Phase notes",
            value=saved_answers.get("__freeform__", ""),
            height=300,
            key=f"recon_freeform_{phase}",
        )

        if st.button("Save phase notes"):
            save_recon_phase_answer(phase, "__freeform__", freeform_notes)
            st.success(f"Saved notes for {phase}")
        if st.button("Delete phase notes", type="secondary"):
            delete_recon_phase_answers(phase)
            st.success(f"Deleted saved notes for {phase}")
            st.rerun()
        return

    with st.form(f"recon_form_{phase}"):
        for index, question in enumerate(questions):
            key = f"recon_{phase}_{index}"
            default = saved_answers.get(question, "")
            st.text_area(question, value=default, height=200, key=key)

        submitted = st.form_submit_button("Save phase answers")

    if submitted:
        for index, question in enumerate(questions):
            key = f"recon_{phase}_{index}"
            save_recon_phase_answer(phase, question, st.session_state.get(key, ""))
        st.success(f"Saved answers for {phase}")

    if st.button("Delete saved answers", type="secondary"):
        delete_recon_phase_answers(phase)
        st.success(f"Deleted saved answers for {phase}")
        st.rerun()


def programs_domains_ui() -> None:
    _ensure_db()
    st.subheader("Programs & domains")
    st.caption(
        "Organize authorized assessment scope and connect testing accounts to application domains."
    )

    with st.form("create_program_form", clear_on_submit=True):
        st.markdown("#### Add program")
        name = st.text_input("Program name")
        scope_notes = st.text_area("Scope notes")
        policy_url = st.text_input("Policy / reference URL")
        status = st.selectbox("Program status", ["active", "paused", "completed"])
        create_submitted = st.form_submit_button("Create program")
    if create_submitted:
        try:
            program_id = create_program(name, scope_notes, policy_url, status)
        except (ValueError, sqlite3.IntegrityError) as exc:
            st.error(f"Could not create program: {exc}")
        else:
            st.success(f"Program created with ID {program_id}.")
            st.rerun()

    programs = get_programs()
    if not programs:
        st.info("Create a program before adding domains.")
        return
    program_by_id = {item["program_id"]: item for item in programs}
    with st.form("create_domain_form", clear_on_submit=True):
        st.markdown("#### Add domain / application")
        program_id = st.selectbox(
            "Program",
            list(program_by_id),
            format_func=lambda value: f"{program_by_id[value]['name']} (ID {value})",
        )
        domain_name = st.text_input("Domain / application name")
        base_url = st.text_input("Base URL or host")
        notes = st.text_area("Domain notes")
        accounts = get_all_accounts()
        account_ids = st.multiselect(
            "Associated accounts",
            [item["id"] for item in accounts],
            format_func=lambda value: next(
                f"{item['account_name']} (ID {value}, role: {item.get('role') or '—'})"
                for item in accounts
                if item["id"] == value
            ),
        )
        domain_submitted = st.form_submit_button("Create domain")
    if domain_submitted:
        try:
            domain_id = create_domain(
                program_id,
                domain_name,
                base_url,
                notes,
                account_ids,
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            st.error(f"Could not create domain: {exc}")
        else:
            st.success(f"Domain created with ID {domain_id}.")
            st.rerun()

    domains = get_domains()
    st.markdown("---")
    st.markdown("#### Saved target contexts")
    for program in programs:
        st.markdown(f"**Program #{program['program_id']}: {program['name']}** ({program['status']})")
        if program.get("scope_notes"):
            st.caption(_redact_secrets(program["scope_notes"]))
        if program.get("policy_url"):
            st.write(program["policy_url"])
        for domain in domains:
            if domain["program_id"] != program["program_id"]:
                continue
            with st.expander(
                f"Domain #{domain['domain_id']}: {domain['name']} — {domain.get('base_url') or 'no base URL'}"
            ):
                st.write(f"Status: {domain['status']}")
                st.write(
                    f"Notes: {_redact_secrets(domain.get('notes') or '—')}"
                )
                linked_ids = [
                    int(value)
                    for value in (domain.get("account_ids") or "").split(",")
                    if value.isdigit()
                ]
                st.write(
                    "Accounts: "
                    + (
                        ", ".join(
                            f"{item['account_name']} ({item.get('role') or 'role not set'})"
                            for item in accounts
                            if item["id"] in linked_ids
                        )
                        or "None linked"
                    )
                )

    if domains:
        st.markdown("---")
        st.markdown("#### Edit domain")
        domain_by_id = {item["domain_id"]: item for item in domains}
        selected_domain_id = st.selectbox(
            "Domain to edit",
            list(domain_by_id),
            format_func=lambda value: (
                f"{domain_by_id[value]['name']} "
                f"(Program: {domain_by_id[value]['program_name']})"
            ),
        )
        selected_domain = domain_by_id[selected_domain_id]
        with st.form(f"edit_domain_{selected_domain_id}"):
            edited_name = st.text_input(
                "Domain / application name",
                value=selected_domain["name"],
            )
            edited_url = st.text_input(
                "Base URL or host",
                value=selected_domain.get("base_url") or "",
            )
            edited_notes = st.text_area(
                "Domain notes",
                value=selected_domain.get("notes") or "",
            )
            edited_status = st.selectbox(
                "Status",
                ["active", "paused", "completed"],
                index=["active", "paused", "completed"].index(selected_domain["status"])
                if selected_domain["status"] in ["active", "paused", "completed"]
                else 0,
            )
            linked_account_ids = [
                int(value)
                for value in (selected_domain.get("account_ids") or "").split(",")
                if value.isdigit()
            ]
            edited_account_ids = st.multiselect(
                "Associated accounts",
                [item["id"] for item in accounts],
                default=linked_account_ids,
                format_func=lambda value: next(
                    f"{item['account_name']} (ID {value})"
                    for item in accounts
                    if item["id"] == value
                ),
            )
            update_submitted = st.form_submit_button("Save domain changes")
        if update_submitted:
            try:
                update_domain(
                    selected_domain_id,
                    edited_name,
                    edited_url,
                    edited_notes,
                    edited_status,
                    edited_account_ids,
                )
            except ValueError as exc:
                st.error(f"Could not update domain: {exc}")
            else:
                st.success("Domain changes saved.")
                st.rerun()
        if st.button("Archive selected domain", key=f"archive_domain_{selected_domain_id}"):
            archive_domain(selected_domain_id)
            st.success("Domain archived; its records are retained.")
            st.rerun()

    st.markdown("---")
    st.markdown("#### Edit program")
    selected_program_id = st.selectbox(
        "Program to edit",
        list(program_by_id),
        format_func=lambda value: f"{program_by_id[value]['name']} (ID {value})",
    )
    selected_program = program_by_id[selected_program_id]
    with st.form(f"edit_program_{selected_program_id}"):
        edited_program_name = st.text_input(
            "Program name",
            value=selected_program["name"],
        )
        edited_scope = st.text_area(
            "Scope notes",
            value=selected_program.get("scope_notes") or "",
        )
        edited_policy = st.text_input(
            "Policy / reference URL",
            value=selected_program.get("policy_url") or "",
        )
        program_statuses = ["active", "paused", "completed"]
        edited_program_status = st.selectbox(
            "Program status",
            program_statuses,
            index=program_statuses.index(selected_program["status"]),
        )
        save_program_submitted = st.form_submit_button("Save program changes")
    if save_program_submitted:
        try:
            update_program(
                selected_program_id,
                edited_program_name,
                edited_scope,
                edited_policy,
                edited_program_status,
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            st.error(f"Could not update program: {exc}")
        else:
            st.success("Program changes saved.")
            st.rerun()
    if st.button("Archive selected program", key=f"archive_program_{selected_program_id}"):
        archive_program(selected_program_id)
        st.success("Program archived; its records are retained.")
        st.rerun()

    st.caption(f"Database schema version: {get_schema_version()}")


def attempt_history_ui() -> None:
    _ensure_db()
    st.subheader("Requests & test history")
    requests = get_all_requests()
    if not requests:
        st.info("Create a request definition before adding captured test history.")
        return
    request_by_id = {item["id"]: item for item in requests}
    request_id = st.selectbox(
        "Request definition",
        list(request_by_id),
        format_func=lambda value: (
            f"Request #{value} — "
            + " ".join((request_by_id[value].get("request") or "").split())[:80]
        ),
    )
    selected_request = request_by_id[request_id]
    st.caption(
        f"Function: {selected_request.get('function_id') or 'unlinked'} · "
        f"Domain: {selected_request.get('domain_id') or 'unlinked'} · "
        f"Account: {selected_request.get('account_id') or 'unlinked'}"
    )
    attempts = get_request_attempts(request_id)
    if not attempts:
        st.info("No attempts recorded. Import a captured Burp message or use the local API.")
        return

    category_filter = st.multiselect(
        "Filter by category",
        sorted(
            {
                name
                for attempt in attempts
                for name in (attempt.get("categories") or "").split(",")
                if name
            }
        ),
    )
    review_filter = st.multiselect(
        "Filter by review state",
        ["unreviewed", "needs_review", "reviewed"],
    )
    filtered = attempts
    if category_filter:
        filtered = [
            item
            for item in filtered
            if set((item.get("categories") or "").split(",")) & set(category_filter)
        ]
    if review_filter:
        filtered = [item for item in filtered if item["review_status"] in review_filter]
    if not filtered:
        st.info("No attempts match the selected filters.")
        return

    for attempt in filtered:
        category_names = attempt.get("categories") or "Uncategorized"
        with st.expander(
            f"Attempt #{attempt['attempt_id']} · {category_names} · {attempt['review_status']} · {attempt['created_at']}"
        ):
            st.write(f"Response status: {attempt.get('response_status') or 'not captured'}")
            st.markdown("**Sent request (secrets masked):**")
            st.code(_redact_secrets(attempt.get("sent_request") or ""), language="text")
            st.markdown("**Diff:**")
            st.code(
                _redact_secrets(
                    attempt.get("diff", {}).get("unified", "")
                    if isinstance(attempt.get("diff"), dict)
                    else str(attempt.get("diff") or "")
                ),
                language="diff",
            )
            if attempt.get("response_headers"):
                st.markdown("**Response headers (secrets masked):**")
                st.code(_redact_secrets(attempt["response_headers"]), language="text")
            if attempt.get("response_body") is not None and st.checkbox(
                "Show captured response body",
                key=f"show_attempt_body_{attempt['attempt_id']}",
            ):
                body = attempt["response_body"]
                st.code(
                    body.decode("utf-8", errors="replace")
                    if isinstance(body, bytes)
                    else str(body),
                    language="text",
                )
            st.write(f"Expected: {_redact_secrets(attempt.get('expected_behavior') or '—')}")
            st.write(f"Observed: {_redact_secrets(attempt.get('observed_behavior') or '—')}")
            st.write(f"Notes: {_redact_secrets(attempt.get('notes') or '—')}")
            with st.form(f"annotate_attempt_{attempt['attempt_id']}"):
                notes = st.text_area(
                    "Notes",
                    value=attempt.get("notes") or "",
                )
                expected = st.text_area(
                    "Expected behavior",
                    value=attempt.get("expected_behavior") or "",
                )
                observed = st.text_area(
                    "Observed behavior",
                    value=attempt.get("observed_behavior") or "",
                )
                review_status = st.selectbox(
                    "Review state",
                    ["unreviewed", "needs_review", "reviewed"],
                    index=["unreviewed", "needs_review", "reviewed"].index(
                        attempt["review_status"]
                    ),
                )
                submitted = st.form_submit_button("Save annotations")
            if submitted:
                update_attempt_annotations(
                    attempt["attempt_id"],
                    notes=notes,
                    expected_behavior=expected,
                    observed_behavior=observed,
                    review_status=review_status,
                )
                st.success("Attempt annotations saved; captured evidence was not changed.")
                st.rerun()


def findings_ui() -> None:
    _ensure_db()
    st.subheader("Findings")
    attempts = get_all_request_attempts()
    with st.form("create_finding_form", clear_on_submit=True):
        title = st.text_input("Finding title")
        description = st.text_area("Description")
        severity = st.selectbox(
            "Severity", ["", "informational", "low", "medium", "high", "critical"]
        )
        impact = st.text_area("Impact")
        report_notes = st.text_area("Report notes")
        attempt_ids = st.multiselect(
            "Supporting attempts",
            [item["attempt_id"] for item in attempts],
            format_func=lambda value: f"Attempt #{value}",
        )
        create_submitted = st.form_submit_button("Create suspected finding")
    if create_submitted:
        try:
            finding_id = create_finding(
                title,
                description,
                "suspected",
                severity,
                impact,
                report_notes,
                attempt_ids,
            )
        except ValueError as exc:
            st.error(f"Could not create finding: {exc}")
        else:
            st.success(
                f"Finding #{finding_id} created as suspected. Confirmation remains an explicit review decision."
            )
            st.rerun()

    findings = get_findings()
    if not findings:
        st.info("No findings recorded.")
        return
    st.markdown("---")
    st.markdown("#### Existing findings")
    finding_by_id = {item["finding_id"]: item for item in findings}
    selected_id = st.selectbox(
        "Finding",
        list(finding_by_id),
        format_func=lambda value: (
            f"#{value} — {finding_by_id[value]['title']} "
            f"({finding_by_id[value]['status']})"
        ),
    )
    selected = finding_by_id[selected_id]
    with st.form(f"edit_finding_{selected_id}"):
        edited_title = st.text_input("Title", value=selected["title"])
        edited_description = st.text_area(
            "Description", value=selected.get("description") or ""
        )
        statuses = ["suspected", "confirmed", "closed", "rejected"]
        edited_status = st.selectbox(
            "Status",
            statuses,
            index=statuses.index(selected["status"]),
        )
        edited_severity = st.text_input(
            "Severity", value=selected.get("severity") or ""
        )
        edited_impact = st.text_area("Impact", value=selected.get("impact") or "")
        edited_report_notes = st.text_area(
            "Report notes", value=selected.get("report_notes") or ""
        )
        save_submitted = st.form_submit_button("Save finding")
    if save_submitted:
        try:
            update_finding(
                selected_id,
                title=edited_title,
                description=edited_description,
                status=edited_status,
                severity=edited_severity,
                impact=edited_impact,
                report_notes=edited_report_notes,
            )
        except ValueError as exc:
            st.error(f"Could not update finding: {exc}")
        else:
            st.success("Finding updated.")
            st.rerun()
    if st.button("Archive finding", key=f"archive_finding_{selected_id}"):
        archive_finding(selected_id)
        st.success("Finding archived.")
        st.rerun()


def accounts_ui() -> None:
    _ensure_db()
    st.subheader("Accounts & credentials")

    with st.form("save_account_form", clear_on_submit=True):
        account_name = st.text_input("Account name")
        email = st.text_input("Email")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        role = st.text_input("Role")
        org = st.text_input("Organization / Team")
        account_type = st.text_input("Account type (free, paid, owner, member, etc.)")
        notes = st.text_area("Related details / notes", height=180)
        submitted = st.form_submit_button("Save account")

    if submitted:
        if not account_name.strip():
            st.warning("Account name is required.")
            return

        account_id = save_account(
            account_name=account_name,
            email=email,
            username=username,
            password=password,
            role=role,
            org=org,
            account_type=account_type,
            notes=notes,
        )
        st.success(f"Account saved with ID: {account_id}")

    st.markdown("---")
    st.subheader("Saved accounts")

    accounts = get_all_accounts()
    if not accounts:
        st.info("No accounts saved yet.")
        return

    account_search = st.sidebar.text_input("Search accounts", placeholder="Name, email, org, role, notes")
    filtered_accounts = _filter_by_search(
        accounts,
        ["account_name", "email", "username", "role", "org", "account_type", "notes"],
        account_search,
    )

    if not filtered_accounts:
        st.warning("No accounts match your search.")
        return

    account_ids = [acc["id"] for acc in filtered_accounts]
    selected_id = st.sidebar.selectbox("Account list", account_ids, format_func=lambda x: f"Account #{x}")

    selected = next(acc for acc in filtered_accounts if acc["id"] == selected_id)
    st.markdown(f"### Account #{selected['id']} — {selected.get('account_name', 'Unnamed')}")
    st.write(f"Email: {selected.get('email') or '—'}")
    st.write(f"Username: {selected.get('username') or '—'}")
    st.write(
        "Password: stored locally"
        if selected.get("password")
        else "Password: not stored"
    )
    if selected.get("password"):
        st.warning(
            "This legacy account password is stored as plaintext in SQLite. "
            "The interface and API hide it, but protect the database file."
        )
    st.write(f"Role: {selected.get('role') or '—'}")
    st.write(f"Org: {selected.get('org') or '—'}")
    st.write(f"Type: {selected.get('account_type') or '—'}")
    st.write("Notes:")
    st.code(_redact_secrets(selected.get("notes") or "No notes."), language="text")

    account_objects = get_objects_for_account(selected_id)
    object_by_id = {item["object_id"]: item for item in account_objects}

    st.markdown("---")
    st.subheader("Objects hierarchy")
    st.caption("Objects can be nested to any depth and each object belongs to this account.")

    def render_object_tree(parent_id: int | None = None, level: int = 0) -> None:
        children = [
            item for item in account_objects if item.get("parent_object_id") == parent_id
        ]
        for item in children:
            prefix = "  " * level
            st.markdown(f"{prefix}- **{item['object_name']}** (Object ID: `{item['object_id']}`)")
            if item.get("notes"):
                st.caption(f"{prefix}{_redact_secrets(item['notes'])}")
            render_object_tree(item["object_id"], level + 1)

    if account_objects:
        render_object_tree()
    else:
        st.info("No objects saved for this account yet.")

    with st.form(f"add_object_{selected_id}", clear_on_submit=True):
        st.markdown("#### Add object")
        object_name = st.text_input("Object name")
        parent_options = [None, *object_by_id]
        parent_object_id = st.selectbox(
            "Parent object",
            parent_options,
            format_func=lambda value: "Top level" if value is None else (
                f"{object_by_id[value]['object_name']} (ID {value})"
            ),
        )
        object_notes = st.text_area("Object notes", height=120)
        object_submitted = st.form_submit_button("Save object")

    if object_submitted:
        try:
            object_id = save_object(object_name, selected_id, parent_object_id, object_notes)
        except ValueError as exc:
            st.warning(str(exc))
        else:
            st.success(f"Object saved with ID: {object_id}")
            st.rerun()

    if account_objects:
        st.markdown("#### Edit object")
        edit_object_id = st.selectbox(
            "Object to edit",
            list(object_by_id),
            format_func=lambda value: f"{object_by_id[value]['object_name']} (ID {value})",
            key=f"edit_object_select_{selected_id}",
        )
        selected_object = object_by_id[edit_object_id]
        valid_parents = [
            None,
            *[
                item_id
                for item_id in object_by_id
                if item_id != edit_object_id
            ],
        ]
        with st.form(f"edit_object_{selected_id}_{edit_object_id}"):
            edited_object_name = st.text_input(
                "Object name",
                value=selected_object.get("object_name") or "",
            )
            edited_parent_id = st.selectbox(
                "Parent object",
                valid_parents,
                index=valid_parents.index(selected_object.get("parent_object_id"))
                if selected_object.get("parent_object_id") in valid_parents else 0,
                format_func=lambda value: "Top level" if value is None else (
                    f"{object_by_id[value]['object_name']} (ID {value})"
                ),
            )
            edited_object_notes = st.text_area(
                "Object notes",
                value=selected_object.get("notes") or "",
                height=120,
            )
            object_update_submitted = st.form_submit_button("Update object")

        if object_update_submitted:
            try:
                update_object(
                    edit_object_id,
                    edited_object_name,
                    edited_parent_id,
                    edited_object_notes,
                )
            except ValueError as exc:
                st.warning(str(exc))
            else:
                st.success(f"Object #{edit_object_id} updated")
                st.rerun()

    st.markdown("---")
    st.subheader("Edit selected account")
    with st.form(f"edit_account_{selected_id}"):
        ed_account_name = st.text_input("Account name", value=selected.get("account_name") or "")
        ed_email = st.text_input("Email", value=selected.get("email") or "")
        ed_username = st.text_input("Username", value=selected.get("username") or "")
        ed_password = st.text_input(
            "New password (leave blank to keep current)",
            value="",
            type="password",
        )
        ed_role = st.text_input("Role", value=selected.get("role") or "")
        ed_org = st.text_input("Organization / Team", value=selected.get("org") or "")
        ed_account_type = st.text_input("Account type", value=selected.get("account_type") or "")
        ed_notes = st.text_area("Related details / notes", value=selected.get("notes") or "", height=180)
        update_submitted = st.form_submit_button("Update account")

    if update_submitted:
        update_account(
            selected_id,
            ed_account_name,
            ed_email,
            ed_username,
            ed_password if ed_password else selected.get("password") or "",
            ed_role,
            ed_org,
            ed_account_type,
            ed_notes,
        )
        st.success(f"Account #{selected_id} updated")

    if st.button("Delete selected account", type="secondary"):
        delete_account(selected_id)
        st.success(f"Account #{selected_id} deleted")
        st.rerun()


def _get_account_objects() -> list[dict]:
    objects = []
    for account in get_all_accounts():
        for item in get_objects_for_account(account["id"]):
            item["account_name"] = account["account_name"]
            objects.append(item)
    return objects


def add_function_ui() -> None:
    _ensure_db()
    st.subheader("Add function")

    objects = _get_account_objects()
    if not objects:
        st.info("Create an account and at least one object before adding a function.")
        return

    object_ids = [item["object_id"] for item in objects]
    object_by_id = {item["object_id"]: item for item in objects}
    with st.form("add_function_form", clear_on_submit=True):
        function_name = st.text_input("Function name")
        object_ids = st.multiselect(
            "Objects this function works with",
            object_ids,
            format_func=lambda value: (
                f"{object_by_id[value]['object_name']} "
                f"(Object ID {value}, Account: {object_by_id[value]['account_name']})"
            ),
        )
        function_boundries_created = st.text_area("Function boundaries created", height=140)
        notes = st.text_area("Function notes", height=160)
        st.markdown("#### Optional first request")
        initial_request = st.text_area("Full request", height=140)
        initial_testing_space = st.text_area(
            "Bug type / testing space / notes",
            height=120,
        )
        st.markdown("##### Checklist")
        checklist_columns = st.columns(3)
        for index, class_name in enumerate(get_request_class_columns()):
            with checklist_columns[index % 3]:
                st.checkbox(
                    f"Relevant for {class_name}",
                    key=f"initial_function_request_{class_name}",
                )
        submitted = st.form_submit_button("Save function")

    if submitted:
        try:
            if not object_ids:
                st.warning("Select at least one object for this function.")
                return
            function_id = save_function(
                function_name,
                function_boundries_created,
                notes,
                object_ids[0],
            )
            update_function(
                function_id,
                function_name,
                function_boundries_created,
                notes,
                object_ids[0],
                object_ids=object_ids,
            )
            if initial_request.strip():
                checklist_values = {
                    class_name: st.session_state.get(
                        f"initial_function_request_{class_name}", False
                    )
                    for class_name in get_request_class_columns()
                }
                add_request(
                    request=initial_request,
                    testing_space=initial_testing_space,
                    function_id=function_id,
                    **checklist_values,
                )
        except ValueError as exc:
            st.warning(str(exc))
        else:
            st.success(
                f"Function #{function_id} saved. Open View/Edit Functions to attach requests."
            )


def _request_checklist_fields(request: dict) -> list[str]:
    return [
        field
        for field in get_request_class_columns()
        if field in request or field not in {"function_id"}
    ]


def _save_function_request(function_id: int, request_text: str, testing_space: str, key_prefix: str) -> None:
    if not request_text.strip():
        st.warning("Please enter a request before saving.")
        return

    checklist_values = {
        field: st.session_state.get(f"{key_prefix}_{field}", False)
        for field in get_request_class_columns()
    }
    add_request(
        request=request_text,
        testing_space=testing_space,
        function_id=function_id,
        **checklist_values,
    )
    st.success("Request and checklist saved.")
    st.rerun()


def _render_function_requests(function: dict) -> None:
    function_id = function["function_id"]
    requests = get_requests_for_function(function_id)
    class_columns = get_request_class_columns()

    st.markdown("---")
    st.subheader("Requests and testing checklist")
    st.caption("This uses the request and checklist structure from modules_V1.")

    with st.form(f"add_function_request_{function_id}", clear_on_submit=True):
        request_text = st.text_area("Full request", height=160)
        testing_space = st.text_area(
            "Bug type / testing space / notes",
            height=140,
        )
        st.markdown("#### Checklist")
        columns = st.columns(3)
        for index, class_name in enumerate(class_columns):
            with columns[index % 3]:
                st.checkbox(
                    f"Relevant for {class_name}",
                    key=f"new_function_request_{function_id}_{class_name}",
                )
        request_submitted = st.form_submit_button("Add request to function")

    if request_submitted:
        _save_function_request(
            function_id,
            request_text,
            testing_space,
            f"new_function_request_{function_id}",
        )

    if not requests:
        st.info("No requests are attached to this function yet.")
        return

    for request in requests:
        request_id = request["id"]
        with st.expander(f"Request #{request_id}"):
            with st.form(f"edit_function_request_{request_id}"):
                edited_request = st.text_area(
                    "Full request",
                    value=request.get("request") or "",
                    height=160,
                    key=f"edit_request_text_{request_id}",
                )
                edited_testing_space = st.text_area(
                    "Bug type / testing space / notes",
                    value=request.get("testing_space") or "",
                    height=140,
                    key=f"edit_request_space_{request_id}",
                )
                st.markdown("#### Checklist")
                columns = st.columns(3)
                for index, class_name in enumerate(class_columns):
                    with columns[index % 3]:
                        st.checkbox(
                            f"Relevant for {class_name}",
                            value=bool(request.get(class_name)),
                            key=f"edit_request_{request_id}_{class_name}",
                        )
                request_update_submitted = st.form_submit_button("Save request changes")

            if request_update_submitted:
                try:
                    update_request(request_id, edited_request, edited_testing_space)
                    for class_name in class_columns:
                        update_vuln(
                            request_id,
                            class_name,
                            st.session_state.get(f"edit_request_{request_id}_{class_name}", False),
                        )
                except ValueError as exc:
                    st.warning(str(exc))
                else:
                    st.success(f"Request #{request_id} updated.")
                    st.rerun()


def view_edit_functions_ui() -> None:
    _ensure_db()
    st.subheader("View and edit functions")

    functions = get_all_functions()
    if not functions:
        st.info("No functions saved yet. Use Add Function first.")
        return

    function_ids = [function["function_id"] for function in functions]
    function_by_id = {function["function_id"]: function for function in functions}
    selected_id = st.sidebar.selectbox(
        "Function list",
        function_ids,
        format_func=lambda value: (
            f"Function #{value}: {function_by_id[value]['function_name']}"
        ),
    )
    selected = function_by_id[selected_id]
    st.markdown(f"### Function #{selected_id}")

    objects = _get_account_objects()
    object_by_id = {item["object_id"]: item for item in objects}
    object_ids = list(object_by_id)
    current_object_ids = [
        object_id for object_id in get_object_ids_for_function(selected_id)
        if object_id in object_by_id
    ]
    if not current_object_ids and object_ids:
        st.warning("Select at least one object for this function.")

    with st.form(f"edit_function_{selected_id}"):
        edited_name = st.text_input(
            "Function name",
            value=selected.get("function_name") or "",
        )
        edited_object_ids = st.multiselect(
            "Objects this function works with",
            object_ids,
            default=current_object_ids,
            format_func=lambda value: (
                f"{object_by_id[value]['object_name']} "
                f"(Object ID {value}, Account: {object_by_id[value]['account_name']})"
            ),
            disabled=not object_ids,
        )
        edited_boundaries = st.text_area(
            "Function boundaries created",
            value=selected.get("function_boundries_created") or "",
            height=140,
        )
        edited_notes = st.text_area(
            "Function notes",
            value=selected.get("notes") or "",
            height=160,
        )
        function_update_submitted = st.form_submit_button("Save function changes")

    if function_update_submitted:
        try:
            update_function(
                selected_id,
                edited_name,
                edited_boundaries,
                edited_notes,
                edited_object_ids[0] if edited_object_ids else None,
                object_ids=edited_object_ids,
            )
        except ValueError as exc:
            st.warning(str(exc))
        else:
            st.success(f"Function #{selected_id} updated.")
            st.rerun()

    _render_function_requests(selected)


def test_categories_ui() -> None:
    _ensure_db()
    st.subheader("Test categories")
    st.caption(
        "Categories apply to individual captured attempts. Selecting a category does not confirm a vulnerability."
    )
    with st.form("add_test_category_form", clear_on_submit=True):
        name = st.text_input("Category name")
        submitted = st.form_submit_button("Add category")
    if submitted:
        try:
            category_id = create_test_category(name)
        except (ValueError, sqlite3.IntegrityError) as exc:
            st.error(f"Could not add category: {exc}")
        else:
            st.success(f"Category created with ID {category_id}.")
            st.rerun()

    for category in get_test_categories():
        name_col, kind_col, action_col = st.columns([4, 2, 1])
        name_col.write(category["name"])
        kind_col.write("Built-in" if category["built_in"] else "Custom")
        if not category["built_in"] and action_col.button(
            "Delete",
            key=f"delete_test_category_{category['category_id']}",
        ):
            try:
                delete_test_category(category["category_id"])
            except (ValueError, sqlite3.IntegrityError) as exc:
                st.error(str(exc))
            else:
                st.success("Category deleted.")
                st.rerun()


def _map_node_style(node_kind: str) -> dict:
    styles = {
        "program": {"background": "#D94F70", "color": "#FFFFFF", "border": "2px solid #8E2945"},
        "domain": {"background": "#5A67A5", "color": "#FFFFFF", "border": "2px solid #394273"},
        "account": {"background": "#12343B", "color": "#F4F7F5", "border": "2px solid #4CB7A5"},
        "object": {"background": "#F2C14E", "color": "#1E2328", "border": "2px solid #B78312"},
        "function": {"background": "#D97A4A", "color": "#FFFFFF", "border": "2px solid #9B4320"},
        "request": {"background": "#E7EDF0", "color": "#1E2328", "border": "2px solid #8B9AA5"},
        "attempt": {"background": "#C7E9B0", "color": "#1E2328", "border": "2px solid #588157"},
        "finding": {"background": "#F4A261", "color": "#1E2328", "border": "2px solid #A44A16"},
        "legacy": {"background": "#D7D7D7", "color": "#333333", "border": "2px dashed #777777"},
    }
    return {
        **styles[node_kind],
        "borderRadius": "8px",
        "padding": "10px",
        "fontSize": "13px",
        "width": "220px",
        "height": "72px",
        "boxSizing": "border-box",
    }


def _map_node_content(node_kind: str, label: str, identifier: int) -> str:
    return f"{node_kind.upper()} #{identifier}\n{label}"


def _coerce_flow_state(value, fallback_nodes, fallback_edges) -> StreamlitFlowState:
    if isinstance(value, StreamlitFlowState):
        existing_edge_ids = {edge.id for edge in value.edges}
        value.edges.extend(
            edge for edge in fallback_edges if edge.id not in existing_edge_ids
        )
        return value

    if not isinstance(value, dict):
        return StreamlitFlowState(fallback_nodes, fallback_edges)

    nodes = [
        node if isinstance(node, StreamlitFlowNode) else StreamlitFlowNode.from_dict(node)
        for node in value.get("nodes", [])
    ]
    edges = [
        edge if isinstance(edge, StreamlitFlowEdge) else StreamlitFlowEdge.from_dict(edge)
        for edge in value.get("edges", [])
    ]
    existing_edge_ids = {edge.id for edge in edges}
    edges.extend(edge for edge in fallback_edges if edge.id not in existing_edge_ids)
    return StreamlitFlowState(
        nodes=nodes or fallback_nodes,
        edges=edges or fallback_edges,
        selected_id=value.get("selected_id", value.get("selectedId")),
        timestamp=value.get("timestamp", 0),
    )


def mind_map_ui() -> None:
    _ensure_db()
    st.subheader("Program and testing mind map")
    st.caption(
        "Program/domain hierarchy, testing relationships, and legacy records. "
        "Select a node for details; drag, pan, and zoom as needed."
    )

    programs = get_programs()
    domains = get_domains()
    accounts = get_all_accounts()
    objects = get_all_objects()
    functions = get_all_functions()
    requests = get_all_requests()
    attempts = get_all_request_attempts()
    findings = get_findings()

    nodes = []
    edges = []
    node_details = {}

    origin_id = "program-origin"
    nodes.append(
        StreamlitFlowNode(
            origin_id,
            (0, 0),
            {"content": "PROGRAM\nAssessment workspace"},
            node_type="input",
            selectable=True,
            style={
                "background": "#D94F70",
                "color": "#FFFFFF",
                "border": "3px solid #8E2945",
                "borderRadius": "10px",
                "padding": "14px",
                "fontSize": "15px",
                "fontWeight": "700",
                "width": "240px",
                "height": "78px",
                "boxSizing": "border-box",
            },
        )
    )
    node_details[origin_id] = {
        "type": "Origin",
        "name": "PROGRAM",
        "notes": "Static origin for saved program contexts.",
    }

    for program in programs:
        node_id = f"program-{program['program_id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {"content": _map_node_content("program", program["name"], program["program_id"])},
                selectable=True,
                style=_map_node_style("program"),
            )
        )
        edges.append(
            StreamlitFlowEdge(
                f"edge-{origin_id}-{node_id}",
                origin_id,
                node_id,
                edge_type="smoothstep",
            )
        )
        node_details[node_id] = {
            "type": "Program",
            "id": program["program_id"],
            "name": program["name"],
            "status": program["status"],
            "scope": _redact_secrets(program.get("scope_notes") or "No scope notes."),
            "policy_url": program.get("policy_url") or "No policy URL.",
        }

    for domain in domains:
        node_id = f"domain-{domain['domain_id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {"content": _map_node_content("domain", domain["name"], domain["domain_id"])},
                selectable=True,
                style=_map_node_style("domain"),
            )
        )
        source_id = f"program-{domain['program_id']}"
        edges.append(
            StreamlitFlowEdge(
                f"edge-{source_id}-{node_id}",
                source_id,
                node_id,
                edge_type="smoothstep",
            )
        )
        node_details[node_id] = {
            "type": "Domain / Application",
            "id": domain["domain_id"],
            "name": domain["name"],
            "program": domain["program_name"],
            "base_url": domain.get("base_url") or "No base URL.",
            "status": domain["status"],
            "notes": _redact_secrets(domain.get("notes") or "No notes."),
        }

    legacy_id = "legacy-records"
    legacy_added = False

    def add_legacy_group() -> None:
        nonlocal legacy_added
        if legacy_added:
            return
        nodes.append(
            StreamlitFlowNode(
                legacy_id,
                (0, 0),
                {"content": "LEGACY / UNLINKED\nNeeds context"},
                selectable=True,
                style=_map_node_style("legacy"),
            )
        )
        edges.append(
            StreamlitFlowEdge(
                f"edge-{origin_id}-{legacy_id}",
                origin_id,
                legacy_id,
                edge_type="smoothstep",
            )
        )
        node_details[legacy_id] = {
            "type": "Legacy group",
            "name": "Legacy / unlinked records",
            "notes": "Older records that have not been connected to a domain or parent.",
        }
        legacy_added = True

    for account in accounts:
        node_id = f"account-{account['id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {"content": _map_node_content("account", account["account_name"], account["id"])},
                node_type="input",
                selectable=True,
                style=_map_node_style("account"),
            )
        )
        linked_domains = [
            domain
            for domain in domains
            if str(account["id"]) in (domain.get("account_ids") or "").split(",")
        ]
        if linked_domains:
            for domain in linked_domains:
                source_id = f"domain-{domain['domain_id']}"
                edges.append(
                    StreamlitFlowEdge(
                        f"edge-{source_id}-{node_id}",
                        source_id,
                        node_id,
                        edge_type="smoothstep",
                    )
                )
        else:
            add_legacy_group()
            edges.append(
                StreamlitFlowEdge(
                    f"edge-{legacy_id}-{node_id}",
                    legacy_id,
                    node_id,
                    edge_type="smoothstep",
                )
            )
        node_details[node_id] = {
            "type": "Account",
            "id": account["id"],
            "name": account["account_name"],
            "role": account.get("role") or "Role not set.",
            "legacy": "Account is not linked to a domain." if not linked_domains else "",
            "notes": _redact_secrets(account.get("notes") or "No notes."),
        }

    object_by_id = {item["object_id"]: item for item in objects}
    for item in objects:
        node_id = f"object-{item['object_id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {
                    "content": _map_node_content(
                        "object",
                        f"{'[archived] ' if item.get('archived_at') else ''}{item['object_name']}",
                        item["object_id"],
                    )
                },
                selectable=True,
                style=_map_node_style("object"),
            )
        )
        parent_id = item.get("parent_object_id")
        account_id = item.get("account_id")
        account_node_id = f"account-{account_id}"
        if parent_id in object_by_id:
            source_id = f"object-{parent_id}"
        elif account_id and any(account["id"] == account_id for account in accounts):
            source_id = account_node_id
        else:
            add_legacy_group()
            source_id = legacy_id
        edges.append(StreamlitFlowEdge(f"edge-{source_id}-{node_id}", source_id, node_id, edge_type="smoothstep"))
        node_details[node_id] = {
            "type": "Object",
            "id": item["object_id"],
            "name": item["object_name"],
            "status": "archived" if item.get("archived_at") else "active",
            "account": item.get("account_name") or "",
            "parent_id": item.get("parent_object_id") or "Top level",
            "notes": _redact_secrets(item.get("notes") or "No notes."),
        }

    function_by_id = {item["function_id"]: item for item in functions}
    for function in functions:
        node_id = f"function-{function['function_id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {"content": _map_node_content("function", function["function_name"], function["function_id"])},
                selectable=True,
                style=_map_node_style("function"),
            )
        )
        linked_object_ids = [
            int(object_id)
            for object_id in (function.get("object_ids") or "").split(",")
            if object_id.strip().isdigit() and int(object_id) in object_by_id
        ]
        if not linked_object_ids and function.get("object_id") in object_by_id:
            linked_object_ids = [function["object_id"]]
        for linked_object_id in linked_object_ids:
            source_id = f"object-{linked_object_id}"
            edges.append(StreamlitFlowEdge(f"edge-{source_id}-{node_id}", source_id, node_id, edge_type="smoothstep"))
        if not linked_object_ids:
            add_legacy_group()
            edges.append(
                StreamlitFlowEdge(
                    f"edge-{legacy_id}-{node_id}",
                    legacy_id,
                    node_id,
                    edge_type="smoothstep",
                )
            )
        node_details[node_id] = {
            "type": "Function",
            "id": function["function_id"],
            "name": function["function_name"],
            "object": function.get("object_name") or "Unlinked object",
            "boundaries": function.get("function_boundries_created") or "No boundaries recorded.",
            "notes": _redact_secrets(function.get("notes") or "No notes."),
        }

    for request in requests:
        node_id = f"request-{request['id']}"
        request_label = " ".join((request.get("request") or "").split())
        if len(request_label) > 54:
            request_label = f"{request_label[:51]}..."
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {"content": _map_node_content("request", _redact_secrets(request_label) or "Empty request", request["id"])},
                selectable=True,
                style=_map_node_style("request"),
            )
        )
        if request.get("function_id") in function_by_id:
            source_id = f"function-{request['function_id']}"
        elif request.get("object_id") in object_by_id:
            source_id = f"object-{request['object_id']}"
        elif request.get("domain_id") and any(
            item["domain_id"] == request["domain_id"] for item in domains
        ):
            source_id = f"domain-{request['domain_id']}"
        elif request.get("account_id") and any(
            item["id"] == request["account_id"] for item in accounts
        ):
            source_id = f"account-{request['account_id']}"
        else:
            add_legacy_group()
            source_id = legacy_id
        edges.append(StreamlitFlowEdge(f"edge-{source_id}-{node_id}", source_id, node_id, edge_type="smoothstep"))
        node_details[node_id] = {
            "type": "Request",
            "id": request["id"],
            "function_id": request["function_id"],
            "request": _redact_secrets(request.get("request") or "Empty request"),
            "testing_space": _redact_secrets(request.get("testing_space") or "No testing-space notes."),
            "checklist": ", ".join(
                key for key in get_request_class_columns() if request.get(key)
            ) or "No checklist classes selected.",
        }

    request_ids = {request["id"] for request in requests}
    for attempt in attempts:
        node_id = f"attempt-{attempt['attempt_id']}"
        category_names = attempt.get("categories") or ""
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {
                    "content": _map_node_content(
                        "attempt",
                        f"{attempt['review_status']} · {category_names or 'uncategorized'}",
                        attempt["attempt_id"],
                    )
                },
                selectable=True,
                style=_map_node_style("attempt"),
            )
        )
        if attempt.get("request_id") in request_ids:
            source_id = f"request-{attempt['request_id']}"
            edges.append(
                StreamlitFlowEdge(
                    f"edge-{source_id}-{node_id}",
                    source_id,
                    node_id,
                    edge_type="smoothstep",
                )
            )
        else:
            add_legacy_group()
            edges.append(
                StreamlitFlowEdge(
                    f"edge-{legacy_id}-{node_id}",
                    legacy_id,
                    node_id,
                    edge_type="smoothstep",
                )
            )
        node_details[node_id] = {
            "type": "Test attempt",
            "id": attempt["attempt_id"],
            "request_id": attempt.get("request_id") or "Legacy / deleted request",
            "categories": category_names or "Uncategorized",
            "response_status": attempt.get("response_status") or "Not captured",
            "review_status": attempt["review_status"],
            "created_at": attempt["created_at"],
            "notes": _redact_secrets(attempt.get("notes") or "No notes."),
        }

    for finding in findings:
        node_id = f"finding-{finding['finding_id']}"
        nodes.append(
            StreamlitFlowNode(
                node_id,
                (0, 0),
                {
                    "content": _map_node_content(
                        "finding",
                        f"{finding['status']}: {finding['title']}",
                        finding["finding_id"],
                    )
                },
                selectable=True,
                style=_map_node_style("finding"),
            )
        )
        for attempt_id in (finding.get("attempt_ids") or "").split(","):
            if attempt_id.isdigit() and int(attempt_id) in {
                item["attempt_id"] for item in attempts
            }:
                source_id = f"attempt-{attempt_id}"
                edges.append(
                    StreamlitFlowEdge(
                        f"edge-{source_id}-{node_id}",
                        source_id,
                        node_id,
                        edge_type="smoothstep",
                    )
                )
        node_details[node_id] = {
            "type": "Finding",
            "id": finding["finding_id"],
            "title": finding["title"],
            "status": finding["status"],
            "severity": finding.get("severity") or "Not set",
            "impact": finding.get("impact") or "No impact notes.",
            "report_notes": _redact_secrets(
                finding.get("report_notes") or "No report notes."
            ),
        }

    if not nodes:
        st.info("Create an account, object, or function to populate the mind map.")
        return

    domain_options = {item["domain_id"]: item["name"] for item in domains}
    account_options = {
        item["id"]: f"{item['account_name']} ({item.get('role') or 'role not set'})"
        for item in accounts
    }
    categories = get_test_categories()
    category_options = {
        item["category_id"]: item["name"] for item in categories
    }
    finding_statuses = sorted({item["status"] for item in findings})
    filter_cols = st.columns(4)
    selected_domain_ids = filter_cols[0].multiselect(
        "Filter domains", list(domain_options), format_func=lambda value: domain_options[value]
    )
    selected_account_ids = filter_cols[1].multiselect(
        "Filter accounts / roles",
        list(account_options),
        format_func=lambda value: account_options[value],
    )
    selected_category_ids = filter_cols[2].multiselect(
        "Filter test categories",
        list(category_options),
        format_func=lambda value: category_options[value],
    )
    search_query = filter_cols[3].text_input("Search nodes")
    status_cols = st.columns(2)
    selected_review_statuses = status_cols[0].multiselect(
        "Filter testing status",
        ["unreviewed", "needs_review", "reviewed"],
    )
    selected_finding_statuses = status_cols[1].multiselect(
        "Filter finding status", finding_statuses
    )

    all_node_ids = {node.id for node in nodes}
    all_edges = [(edge.source, edge.target) for edge in edges]

    def related_nodes(root_ids: set[str]) -> set[str]:
        ancestors = set(root_ids)
        changed = True
        while changed:
            changed = False
            for source, target in all_edges:
                if target in ancestors and source not in ancestors:
                    ancestors.add(source)
                    changed = True
        descendants = set(root_ids)
        changed = True
        while changed:
            changed = False
            for source, target in all_edges:
                if source in descendants and target not in descendants:
                    descendants.add(target)
                    changed = True
        return ancestors | descendants

    visible_node_ids = set(all_node_ids)
    has_filters = bool(
        selected_domain_ids
        or selected_account_ids
        or selected_category_ids
        or search_query.strip()
        or selected_review_statuses
        or selected_finding_statuses
    )
    if selected_domain_ids:
        visible_node_ids &= related_nodes(
            {f"domain-{value}" for value in selected_domain_ids}
        )
    if selected_account_ids:
        visible_node_ids &= related_nodes(
            {f"account-{value}" for value in selected_account_ids}
        )
    if selected_category_ids:
        category_names = {
            category_options[value] for value in selected_category_ids
        }
        matching_attempts = {
            f"attempt-{item['attempt_id']}"
            for item in attempts
            if category_names & set((item.get("categories") or "").split(","))
        }
        visible_node_ids &= related_nodes(matching_attempts)
    if selected_review_statuses:
        matching_attempts = {
            f"attempt-{item['attempt_id']}"
            for item in attempts
            if item["review_status"] in selected_review_statuses
        }
        visible_node_ids &= related_nodes(matching_attempts)
    if selected_finding_statuses:
        matching_findings = {
            f"finding-{item['finding_id']}"
            for item in findings
            if item["status"] in selected_finding_statuses
        }
        visible_node_ids &= related_nodes(matching_findings)
    if search_query.strip():
        search_term = search_query.strip().casefold()
        matching_nodes = {
            node_id
            for node_id, details in node_details.items()
            if search_term in " ".join(str(value) for value in details.values()).casefold()
        }
        visible_node_ids &= related_nodes(matching_nodes)
    if has_filters:
        visible_node_ids.add(origin_id)
    nodes = [node for node in nodes if node.id in visible_node_ids]
    edges = [
        edge
        for edge in edges
        if edge.source in visible_node_ids and edge.target in visible_node_ids
    ]
    if not nodes:
        st.info("No graph nodes match the selected filters.")
        return

    layout_direction = st.selectbox(
        "Map direction",
        ["down", "right", "up", "left"],
        format_func=lambda value: value.capitalize(),
    )
    graph_signature = repr(
        (
            [program["program_id"] for program in programs],
            [(domain["domain_id"], domain["program_id"], domain.get("account_ids")) for domain in domains],
            [account["id"] for account in accounts],
            [(item["object_id"], item.get("parent_object_id"), item.get("account_id")) for item in objects],
            [
                (function["function_id"], function.get("object_id"), function.get("object_ids"))
                for function in functions
            ],
            [(request["id"], request.get("function_id")) for request in requests],
            [(attempt["attempt_id"], attempt["review_status"]) for attempt in attempts],
            [(finding["finding_id"], finding["status"]) for finding in findings],
            sorted(visible_node_ids),
        )
    )
    flow_state_key = f"mind_map_state_{layout_direction}_{graph_signature}"
    if flow_state_key not in st.session_state:
        st.session_state[flow_state_key] = StreamlitFlowState(nodes, edges)
    st.session_state[flow_state_key] = _coerce_flow_state(
        st.session_state[flow_state_key],
        nodes,
        edges,
    )

    flow_component_key = f"mind_map_component_{layout_direction}"
    st.session_state[flow_state_key] = streamlit_flow(
        flow_component_key,
        st.session_state[flow_state_key],
        height=680,
        fit_view=True,
        show_controls=True,
        show_minimap=True,
        get_node_on_click=True,
        pan_on_drag=True,
        allow_zoom=True,
        layout=LayeredLayout(
            direction=layout_direction,
            node_node_spacing=120,
            node_layer_spacing=180,
        ),
        hide_watermark=True,
    )
    st.session_state[flow_state_key] = _coerce_flow_state(
        st.session_state[flow_state_key],
        nodes,
        edges,
    )

    if st.session_state[flow_state_key].selected_id in node_details:
        selected_details = node_details[st.session_state[flow_state_key].selected_id]
        st.markdown("---")
        st.subheader(f"Selected {selected_details['type']}")
        for key, value in selected_details.items():
            if key != "type":
                st.write(f"{key.replace('_', ' ').title()}: {value}")


def db_admin_ui() -> None:
    st.title("Manual Framework Notebook")

    pages = [
        "Recon Phases",
        "Programs & Domains",
        "Accounts",
        "Add Function",
        "View/Edit Functions",
        "Requests & Test History",
        "Test Categories",
        "Findings",
        "Mind Map",
        "Add Class Column",
    ]
    page = st.sidebar.radio("Notebook pages", pages)

    if page == "Recon Phases":
        recon_phase_ui()
    elif page == "Programs & Domains":
        programs_domains_ui()
    elif page == "Accounts":
        accounts_ui()
    elif page == "Add Function":
        add_function_ui()
    elif page == "View/Edit Functions":
        view_edit_functions_ui()
    elif page == "Mind Map":
        mind_map_ui()
    elif page == "Requests & Test History":
        attempt_history_ui()
    elif page == "Test Categories":
        test_categories_ui()
    elif page == "Findings":
        findings_ui()
    elif page == "Add Class Column":
        add_vuln_column_ui()
