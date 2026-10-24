import base64
import json
import os
import secrets
import sqlite3
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from modules import db


app = FastAPI(
    title="Manual Framework API",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
)
bearer_scheme = HTTPBearer(auto_error=False)


def require_api_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> None:
    expected_token = os.environ.get("MANUAL_FRAMEWORK_API_TOKEN", "")
    if len(expected_token) < 32:
        raise HTTPException(
            status_code=503,
            detail="API token must contain at least 32 characters",
        )
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not secrets.compare_digest(credentials.credentials, expected_token)
    ):
        raise HTTPException(status_code=401, detail="A valid bearer token is required")


Auth = Depends(require_api_token)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProgramInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    scope_notes: str = ""
    policy_url: str = ""
    status: str = "active"


class ProgramPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    scope_notes: str | None = None
    policy_url: str | None = None
    status: str | None = None


class DomainInput(StrictModel):
    program_id: int
    name: str = Field(min_length=1, max_length=255)
    base_url: str = ""
    notes: str = ""
    status: str = "active"
    account_ids: list[int] = Field(default_factory=list)


class DomainPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = None
    notes: str | None = None
    status: str | None = None
    account_ids: list[int] | None = None


class AccountInput(StrictModel):
    account_name: str = Field(min_length=1, max_length=200)
    email: str = ""
    username: str = ""
    role: str = ""
    org: str = ""
    account_type: str = ""
    notes: str = ""


class AccountPatch(StrictModel):
    account_name: str | None = Field(default=None, min_length=1, max_length=200)
    email: str | None = None
    username: str | None = None
    role: str | None = None
    org: str | None = None
    account_type: str | None = None
    notes: str | None = None


class ObjectInput(StrictModel):
    object_name: str = Field(min_length=1, max_length=255)
    account_id: int
    parent_object_id: int | None = None
    notes: str = ""


class ObjectPatch(StrictModel):
    object_name: str | None = Field(default=None, min_length=1, max_length=255)
    parent_object_id: int | None = None
    notes: str | None = None


class FunctionInput(StrictModel):
    function_name: str = Field(min_length=1, max_length=255)
    function_boundries_created: str = ""
    notes: str = ""
    object_ids: list[int] = Field(default_factory=list)


class FunctionPatch(StrictModel):
    function_name: str | None = Field(default=None, min_length=1, max_length=255)
    function_boundries_created: str | None = None
    notes: str | None = None
    object_ids: list[int] | None = None


class RequestInput(StrictModel):
    request: str = Field(min_length=1, max_length=2_000_000)
    function_id: int | None = None
    domain_id: int | None = None
    account_id: int | None = None
    object_id: int | None = None
    testing_space: str = ""


class RequestPatch(StrictModel):
    request: str | None = Field(default=None, min_length=1)
    function_id: int | None = None
    domain_id: int | None = None
    account_id: int | None = None
    object_id: int | None = None
    testing_space: str | None = None


class AttemptInput(StrictModel):
    request_id: int
    sent_request: str = Field(min_length=1, max_length=2_000_000)
    baseline_request: str = Field(default="", max_length=2_000_000)
    account_id: int | None = None
    test_category_ids: list[int] = Field(default_factory=list)
    response_status: int | None = Field(default=None, ge=100, le=599)
    response_headers: str = Field(default="", max_length=128_000)
    response_body_base64: str | None = Field(default=None, max_length=14_000_000)
    response_body_encoding: str = "binary"
    diff: dict[str, Any] = Field(default_factory=dict)
    notes: str = Field(default="", max_length=100_000)
    expected_behavior: str = Field(default="", max_length=100_000)
    observed_behavior: str = Field(default="", max_length=100_000)
    idempotency_key: str | None = Field(default=None, max_length=200)


class AttemptAnnotations(StrictModel):
    notes: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    review_status: str | None = None


class CategoryInput(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class FindingInput(StrictModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    status: str = "suspected"
    severity: str = ""
    impact: str = ""
    report_notes: str = ""
    attempt_ids: list[int] = Field(default_factory=list)


class FindingPatch(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    impact: str | None = None
    report_notes: str | None = None


class ReconAnswerInput(StrictModel):
    question: str = Field(min_length=1, max_length=2000)
    answer: str = Field(default="", max_length=100_000)


class ReconNotesInput(StrictModel):
    notes: str = Field(default="", max_length=100_000)


def _service_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    status = 404 if "not found" in message else 400
    return HTTPException(status_code=status, detail=message)


def _page(
    items: list[dict],
    limit: int,
    offset: int,
    search: str,
    fields: tuple[str, ...],
) -> dict:
    if search:
        normalized_search = search.casefold()
        items = [
            item
            for item in items
            if any(normalized_search in str(item.get(field) or "").casefold() for field in fields)
        ]
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "limit": limit,
        "offset": offset,
    }


def _public_account(account: dict) -> dict:
    return {key: value for key, value in account.items() if key != "password"}


def _attempt_for_json(attempt: dict) -> dict:
    result = dict(attempt)
    body = result.pop("response_body", None)
    result["response_body_base64"] = (
        base64.b64encode(body).decode("ascii") if body is not None else None
    )
    if isinstance(result.get("diff"), str):
        result["diff"] = json.loads(result["diff"] or "{}")
    return result


def _validate_domain_account(domain_id: int | None, account_id: int | None) -> None:
    if domain_id is not None and not any(
        domain["domain_id"] == domain_id for domain in db.get_domains()
    ):
        raise HTTPException(status_code=404, detail="domain not found")
    if account_id is not None and db.get_account(account_id) is None:
        raise HTTPException(status_code=404, detail="account not found")
    if domain_id is not None and account_id is not None:
        domain = next(item for item in db.get_domains() if item["domain_id"] == domain_id)
        linked_ids = {
            int(value)
            for value in (domain.get("account_ids") or "").split(",")
            if value.isdigit()
        }
        if account_id not in linked_ids:
            raise HTTPException(
                status_code=400,
                detail="account is not associated with the selected domain",
            )


@app.get("/api/v1/health")
def health() -> dict:
    return {
        "status": "ok",
        "api_version": app.version,
        "schema_version": db.get_schema_version(),
    }


@app.get("/api/v1/programs", dependencies=[Auth])
def list_programs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    return _page(db.get_programs(), limit, offset, search, ("name", "scope_notes"))


@app.post("/api/v1/programs", status_code=201, dependencies=[Auth])
def create_program(payload: ProgramInput) -> dict:
    try:
        identifier = db.create_program(**payload.model_dump())
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="program name already exists") from exc
    return next(item for item in db.get_programs() if item["program_id"] == identifier)


@app.get("/api/v1/programs/{program_id}", dependencies=[Auth])
def read_program(program_id: int) -> dict:
    program = next(
        (item for item in db.get_programs() if item["program_id"] == program_id), None
    )
    if program is None:
        raise HTTPException(status_code=404, detail="program not found")
    return program


@app.patch("/api/v1/programs/{program_id}", dependencies=[Auth])
def patch_program(program_id: int, payload: ProgramPatch) -> dict:
    current = read_program(program_id)
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    try:
        db.update_program(
            program_id,
            values["name"],
            values["scope_notes"],
            values["policy_url"],
            values["status"],
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="program name already exists") from exc
    return read_program(program_id)


@app.delete("/api/v1/programs/{program_id}", status_code=204, dependencies=[Auth])
def remove_program(program_id: int) -> None:
    try:
        db.archive_program(program_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/domains", dependencies=[Auth])
def list_domains(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str = "",
    program_id: int | None = None,
) -> dict:
    items = db.get_domains()
    if program_id is not None:
        items = [item for item in items if item["program_id"] == program_id]
    return _page(items, limit, offset, search, ("name", "base_url", "program_name", "notes"))


@app.post("/api/v1/domains", status_code=201, dependencies=[Auth])
def create_domain(payload: DomainInput) -> dict:
    try:
        identifier = db.create_domain(**payload.model_dump())
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="domain name already exists for this program") from exc
    return next(item for item in db.get_domains() if item["domain_id"] == identifier)


@app.get("/api/v1/domains/{domain_id}", dependencies=[Auth])
def read_domain(domain_id: int) -> dict:
    domain = next(
        (item for item in db.get_domains() if item["domain_id"] == domain_id), None
    )
    if domain is None:
        raise HTTPException(status_code=404, detail="domain not found")
    return domain


@app.patch("/api/v1/domains/{domain_id}", dependencies=[Auth])
def patch_domain(domain_id: int, payload: DomainPatch) -> dict:
    current = read_domain(domain_id)
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    account_ids = values.get("account_ids") or ""
    if isinstance(account_ids, str):
        account_ids = [int(value) for value in account_ids.split(",") if value.isdigit()]
    try:
        db.update_domain(
            domain_id,
            values["name"],
            values.get("base_url") or "",
            values.get("notes") or "",
            values["status"],
            account_ids,
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="domain name already exists for this program") from exc
    return read_domain(domain_id)


@app.delete("/api/v1/domains/{domain_id}", status_code=204, dependencies=[Auth])
def remove_domain(domain_id: int) -> None:
    try:
        db.archive_domain(domain_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/accounts", dependencies=[Auth])
def list_accounts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    items = [_public_account(item) for item in db.get_all_accounts()]
    return _page(items, limit, offset, search, ("account_name", "email", "username", "role", "org"))


@app.get("/api/v1/accounts/{account_id}", dependencies=[Auth])
def read_account(account_id: int) -> dict:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    return _public_account(account)


@app.post("/api/v1/accounts", status_code=201, dependencies=[Auth])
def create_account(payload: AccountInput) -> dict:
    try:
        account_id = db.save_account(**payload.model_dump())
    except ValueError as exc:
        raise _service_error(exc) from exc
    account = db.get_account(account_id)
    assert account is not None
    return _public_account(account)


@app.patch("/api/v1/accounts/{account_id}", dependencies=[Auth])
def patch_account(account_id: int, payload: AccountPatch) -> dict:
    current = db.get_account(account_id)
    if current is None:
        raise HTTPException(status_code=404, detail="account not found")
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    db.update_account(
        account_id,
        values["account_name"],
        values.get("email") or "",
        values.get("username") or "",
        current.get("password") or "",
        values.get("role") or "",
        values.get("org") or "",
        values.get("account_type") or "",
        values.get("notes") or "",
    )
    return read_account(account_id)


@app.delete("/api/v1/accounts/{account_id}", status_code=204, dependencies=[Auth])
def remove_account(account_id: int) -> None:
    try:
        db.archive_account(account_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/objects", dependencies=[Auth])
def list_objects(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str = "",
    account_id: int | None = None,
) -> dict:
    accounts = db.get_all_accounts()
    if account_id is not None:
        if db.get_account(account_id) is None:
            raise HTTPException(status_code=404, detail="account not found")
        accounts = [item for item in accounts if item["id"] == account_id]
    items = []
    for account in accounts:
        for item in db.get_objects_for_account(account["id"]):
            items.append({**item, "account_name": account["account_name"]})
    return _page(items, limit, offset, search, ("object_name", "notes", "account_name"))


@app.post("/api/v1/objects", status_code=201, dependencies=[Auth])
def create_object(payload: ObjectInput) -> dict:
    if db.get_account(payload.account_id) is None:
        raise HTTPException(status_code=404, detail="account not found")
    try:
        identifier = db.save_object(
            payload.object_name,
            payload.account_id,
            payload.parent_object_id,
            payload.notes,
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    return next(
        item
        for item in db.get_objects_for_account(payload.account_id)
        if item["object_id"] == identifier
    )


@app.get("/api/v1/objects/{object_id}", dependencies=[Auth])
def read_object(object_id: int) -> dict:
    item = next(
        (
            item
            for item in db.get_all_objects()
            if item["object_id"] == object_id and item.get("archived_at") is None
        ),
        None,
    )
    if item is None:
        raise HTTPException(status_code=404, detail="object not found")
    return item


@app.patch("/api/v1/objects/{object_id}", dependencies=[Auth])
def patch_object(object_id: int, payload: ObjectPatch) -> dict:
    current = read_object(object_id)
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    try:
        db.update_object(
            object_id,
            values["object_name"],
            values.get("parent_object_id"),
            values.get("notes") or "",
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    return next(
        item
        for item in db.get_objects_for_account(current["account_id"])
        if item["object_id"] == object_id
    )


@app.delete("/api/v1/objects/{object_id}", status_code=204, dependencies=[Auth])
def remove_object(object_id: int) -> None:
    try:
        db.archive_object(object_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/functions", dependencies=[Auth])
def list_functions(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    return _page(db.get_all_functions(), limit, offset, search, ("function_name", "notes"))


@app.get("/api/v1/functions/{function_id}", dependencies=[Auth])
def read_function(function_id: int) -> dict:
    function = next(
        (item for item in db.get_all_functions() if item["function_id"] == function_id),
        None,
    )
    if function is None:
        raise HTTPException(status_code=404, detail="function not found")
    return function


@app.post("/api/v1/functions", status_code=201, dependencies=[Auth])
def create_function(payload: FunctionInput) -> dict:
    object_ids = sorted(set(payload.object_ids))
    if object_ids:
        existing = {
            item["object_id"]
            for account in db.get_all_accounts()
            for item in db.get_objects_for_account(account["id"])
        }
        if set(object_ids) - existing:
            raise HTTPException(status_code=400, detail="one or more objects do not exist")
    first_object_id = object_ids[0] if object_ids else None
    function_id = db.save_function(
        payload.function_name,
        payload.function_boundries_created,
        payload.notes,
        first_object_id,
    )
    if len(object_ids) > 1:
        db.update_function(
            function_id,
            payload.function_name,
            payload.function_boundries_created,
            payload.notes,
            first_object_id,
            object_ids=object_ids,
        )
    return next(item for item in db.get_all_functions() if item["function_id"] == function_id)


@app.delete("/api/v1/functions/{function_id}", status_code=204, dependencies=[Auth])
def remove_function(function_id: int) -> None:
    try:
        db.archive_function(function_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.patch("/api/v1/functions/{function_id}", dependencies=[Auth])
def patch_function(function_id: int, payload: FunctionPatch) -> dict:
    current = next(
        (item for item in db.get_all_functions() if item["function_id"] == function_id),
        None,
    )
    if current is None:
        raise HTTPException(status_code=404, detail="function not found")
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    object_ids = values.get("object_ids")
    if payload.object_ids is None:
        object_ids = [
            int(value)
            for value in (current.get("object_ids") or "").split(",")
            if value.isdigit()
        ]
    else:
        object_ids = sorted(set(object_ids))
    existing_objects = {
        item["object_id"]
        for account in db.get_all_accounts()
        for item in db.get_objects_for_account(account["id"])
    }
    if set(object_ids) - existing_objects:
        raise HTTPException(status_code=400, detail="one or more objects do not exist")
    try:
        db.update_function(
            function_id,
            values["function_name"],
            values.get("function_boundries_created") or "",
            values.get("notes") or "",
            object_ids[0] if object_ids else None,
            object_ids=object_ids,
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    return next(item for item in db.get_all_functions() if item["function_id"] == function_id)


@app.get("/api/v1/requests", dependencies=[Auth])
def list_requests(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    return _page(db.get_all_requests(), limit, offset, search, ("request", "testing_space"))


@app.post("/api/v1/requests", status_code=201, dependencies=[Auth])
def create_request(payload: RequestInput) -> dict:
    if payload.function_id is not None and not any(
        item["function_id"] == payload.function_id for item in db.get_all_functions()
    ):
        raise HTTPException(status_code=404, detail="function not found")
    account_id = payload.account_id
    _validate_domain_account(payload.domain_id, account_id)
    if payload.object_id is not None:
        object_record = next(
            (
                item
                for item in db.get_all_objects()
                if item["object_id"] == payload.object_id
                and item.get("archived_at") is None
            ),
            None,
        )
        if object_record is None:
            raise HTTPException(status_code=404, detail="object not found")
        if (
            payload.function_id is not None
            and payload.object_id not in db.get_object_ids_for_function(payload.function_id)
        ):
            raise HTTPException(
                status_code=400,
                detail="object is not linked to the selected function",
            )
        if account_id is not None and object_record["account_id"] != account_id:
            raise HTTPException(status_code=400, detail="object must belong to the selected account")
        account_id = account_id or object_record["account_id"]
        _validate_domain_account(
            payload.domain_id,
            account_id,
        )
    request_id = db.add_request(
        request=payload.request,
        testing_space=payload.testing_space,
        function_id=payload.function_id,
        domain_id=payload.domain_id,
        account_id=account_id,
        object_id=payload.object_id,
    )
    return db.get_request(request_id) or {}


@app.get("/api/v1/requests/{request_id}", dependencies=[Auth])
def read_request(request_id: int) -> dict:
    request = db.get_request(request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="request not found")
    return request


@app.patch("/api/v1/requests/{request_id}", dependencies=[Auth])
def patch_request(request_id: int, payload: RequestPatch) -> dict:
    current = db.get_request(request_id)
    if current is None:
        raise HTTPException(status_code=404, detail="request not found")
    values = {**current, **payload.model_dump(exclude_unset=True, exclude_none=True)}
    function_id = values.get("function_id")
    if function_id is not None and not any(
        item["function_id"] == function_id for item in db.get_all_functions()
    ):
        raise HTTPException(status_code=404, detail="function not found")
    _validate_domain_account(values.get("domain_id"), values.get("account_id"))
    object_id = values.get("object_id")
    if object_id is not None:
        object_record = next(
            (
                item
                for item in db.get_all_objects()
                if item["object_id"] == object_id
                and item.get("archived_at") is None
            ),
            None,
        )
        if object_record is None:
            raise HTTPException(status_code=404, detail="object not found")
        if function_id is not None and object_id not in db.get_object_ids_for_function(function_id):
            raise HTTPException(
                status_code=400,
                detail="object is not linked to the selected function",
            )
        if values.get("account_id") is not None and object_record["account_id"] != values["account_id"]:
            raise HTTPException(status_code=400, detail="object must belong to the selected account")
        _validate_domain_account(
            values.get("domain_id"),
            values.get("account_id") or object_record["account_id"],
        )
    try:
        db.update_request_context(
            request_id,
            function_id=values.get("function_id"),
            domain_id=values.get("domain_id"),
            account_id=values.get("account_id"),
            object_id=object_id,
            request=values["request"],
            testing_space=values.get("testing_space") or "",
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    return db.get_request(request_id) or {}


@app.delete("/api/v1/requests/{request_id}", status_code=204, dependencies=[Auth])
def remove_request(request_id: int) -> None:
    if db.get_request(request_id) is None:
        raise HTTPException(status_code=404, detail="request not found")
    db.archive_request(request_id)


@app.get("/api/v1/requests/{request_id}/attempts", dependencies=[Auth])
def list_attempts(request_id: int) -> list[dict]:
    if db.get_request(request_id) is None and not db.get_request_attempts(request_id):
        raise HTTPException(status_code=404, detail="request not found")
    return [_attempt_for_json(item) for item in db.get_request_attempts(request_id)]


@app.get("/api/v1/attempts", dependencies=[Auth])
def list_all_attempts(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    items = [_attempt_for_json(item) for item in db.get_all_request_attempts()]
    return _page(
        items,
        limit,
        offset,
        search,
        ("request_label", "sent_request", "notes", "categories", "review_status"),
    )


@app.post("/api/v1/requests/{request_id}/attempts", status_code=201, dependencies=[Auth])
def create_attempt(
    request_id: int,
    payload: AttemptInput,
    idempotency_header: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict:
    if request_id != payload.request_id:
        raise HTTPException(status_code=400, detail="request_id does not match the route")
    body = None
    if payload.response_body_base64 is not None:
        try:
            body = base64.b64decode(payload.response_body_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="response body must be valid base64") from exc
        if len(body) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="response body exceeds the 10 MiB limit")
    try:
        attempt_id = db.create_request_attempt(
            request_id=request_id,
            sent_request=payload.sent_request,
            baseline_request=payload.baseline_request,
            account_id=payload.account_id,
            response_status=payload.response_status,
            response_headers=payload.response_headers,
            response_body=body,
            response_body_encoding=payload.response_body_encoding,
            diff=payload.diff,
            notes=payload.notes,
            expected_behavior=payload.expected_behavior,
            observed_behavior=payload.observed_behavior,
            category_ids=payload.test_category_ids,
            idempotency_key=idempotency_header or payload.idempotency_key,
        )
    except ValueError as exc:
        raise _service_error(exc) from exc
    return _attempt_for_json(db.get_request_attempt(attempt_id) or {})


@app.get("/api/v1/attempts/{attempt_id}", dependencies=[Auth])
def read_attempt(attempt_id: int) -> dict:
    attempt = db.get_request_attempt(attempt_id)
    if attempt is None:
        raise HTTPException(status_code=404, detail="attempt not found")
    return _attempt_for_json(attempt)


@app.patch("/api/v1/attempts/{attempt_id}", dependencies=[Auth])
def annotate_attempt(attempt_id: int, payload: AttemptAnnotations) -> dict:
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    try:
        db.update_attempt_annotations(attempt_id, **changes)
    except ValueError as exc:
        raise _service_error(exc) from exc
    return read_attempt(attempt_id)


@app.get("/api/v1/test-categories", dependencies=[Auth])
def list_test_categories() -> list[dict]:
    return db.get_test_categories()


@app.post("/api/v1/test-categories", status_code=201, dependencies=[Auth])
def create_category(payload: CategoryInput) -> dict:
    try:
        category_id = db.create_test_category(payload.name)
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="category already exists") from exc
    return next(
        item for item in db.get_test_categories() if item["category_id"] == category_id
    )


@app.delete(
    "/api/v1/test-categories/{category_id}",
    status_code=204,
    dependencies=[Auth],
)
def remove_category(category_id: int) -> None:
    try:
        db.delete_test_category(category_id)
    except ValueError as exc:
        raise _service_error(exc) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="category is used by a captured attempt",
        ) from exc


@app.put(
    "/api/v1/attempts/{attempt_id}/categories/{category_id}",
    status_code=204,
    dependencies=[Auth],
)
def add_attempt_category(attempt_id: int, category_id: int) -> None:
    try:
        db.link_attempt_category(attempt_id, category_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.delete(
    "/api/v1/attempts/{attempt_id}/categories/{category_id}",
    status_code=204,
    dependencies=[Auth],
)
def remove_attempt_category(attempt_id: int, category_id: int) -> None:
    try:
        db.unlink_attempt_category(attempt_id, category_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/findings", dependencies=[Auth])
def list_findings(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str = "",
) -> dict:
    return _page(db.get_findings(), limit, offset, search, ("title", "description", "status"))


@app.post("/api/v1/findings", status_code=201, dependencies=[Auth])
def create_finding(payload: FindingInput) -> dict:
    try:
        finding_id = db.create_finding(**payload.model_dump())
    except ValueError as exc:
        raise _service_error(exc) from exc
    return next(item for item in db.get_findings() if item["finding_id"] == finding_id)


@app.get("/api/v1/findings/{finding_id}", dependencies=[Auth])
def read_finding(finding_id: int) -> dict:
    finding = next(
        (item for item in db.get_findings() if item["finding_id"] == finding_id), None
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.patch("/api/v1/findings/{finding_id}", dependencies=[Auth])
def patch_finding(finding_id: int, payload: FindingPatch) -> dict:
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    try:
        db.update_finding(finding_id, **fields)
    except ValueError as exc:
        raise _service_error(exc) from exc
    return read_finding(finding_id)


@app.delete("/api/v1/findings/{finding_id}", status_code=204, dependencies=[Auth])
def remove_finding(finding_id: int) -> None:
    try:
        db.archive_finding(finding_id)
    except ValueError as exc:
        raise _service_error(exc) from exc


@app.get("/api/v1/mind-map", dependencies=[Auth])
def mind_map() -> dict:
    programs = db.get_programs()
    domains = db.get_domains()
    accounts = db.get_all_accounts()
    objects = db.get_all_objects()
    functions = db.get_all_functions()
    requests = db.get_all_requests()
    attempts = db.get_all_request_attempts()
    findings = db.get_findings()
    nodes = []
    edges = []

    def add_node(kind: str, identifier: int, name: str, **metadata: Any) -> None:
        nodes.append(
            {"id": f"{kind}-{identifier}", "type": kind, "name": name, **metadata}
        )

    def add_legacy_group() -> None:
        if not any(node["id"] == "legacy-unlinked" for node in nodes):
            add_node("legacy", "unlinked", "Legacy / unlinked records")

    for item in programs:
        add_node("program", item["program_id"], item["name"], status=item["status"])
    for item in domains:
        add_node("domain", item["domain_id"], item["name"], status=item["status"])
        edges.append(
            {
                "source": f"program-{item['program_id']}",
                "target": f"domain-{item['domain_id']}",
                "type": "parent",
            }
        )
        for account_id in (item.get("account_ids") or "").split(","):
            if account_id.isdigit():
                edges.append(
                    {
                        "source": f"domain-{item['domain_id']}",
                        "target": f"account-{account_id}",
                        "type": "context",
                    }
                )
    for item in accounts:
        add_node("account", item["id"], item["account_name"], role=item.get("role") or "")
        if not any(edge["target"] == f"account-{item['id']}" for edge in edges):
            add_legacy_group()
            edges.append(
                {
                    "source": "legacy-unlinked",
                    "target": f"account-{item['id']}",
                    "type": "legacy",
                }
            )
    object_id_set = {item["object_id"] for item in objects}
    active_account_ids = {account["id"] for account in accounts}
    for item in objects:
        add_node(
            "object",
            item["object_id"],
            item["object_name"],
            status="archived" if item.get("archived_at") else "active",
        )
        if item.get("parent_object_id") in object_id_set:
            source = f"object-{item['parent_object_id']}"
        elif item["account_id"] in active_account_ids:
            source = f"account-{item['account_id']}"
        else:
            add_legacy_group()
            source = "legacy-unlinked"
        edges.append({"source": source, "target": f"object-{item['object_id']}", "type": "parent"})
    object_ids = object_id_set
    for item in functions:
        add_node("function", item["function_id"], item["function_name"])
        linked = [
            int(value)
            for value in (item.get("object_ids") or "").split(",")
            if value.isdigit() and int(value) in object_ids
        ]
        for object_id in linked:
            edges.append(
                {
                    "source": f"object-{object_id}",
                    "target": f"function-{item['function_id']}",
                    "type": "association",
                }
            )
        if not linked:
            if not any(node["id"] == "legacy-unlinked" for node in nodes):
                add_node("legacy", "unlinked", "Legacy / unlinked records")
            edges.append(
                {
                    "source": "legacy-unlinked",
                    "target": f"function-{item['function_id']}",
                    "type": "legacy",
                }
            )
    for item in requests:
        if item.get("function_id") is not None and item["function_id"] in {
            function["function_id"] for function in functions
        }:
            source = f"function-{item['function_id']}"
        else:
            domain_exists = item.get("domain_id") in {
                domain["domain_id"] for domain in domains
            }
            account_exists = item.get("account_id") in {
                account["id"] for account in accounts
            }
            object_exists = item.get("object_id") in object_ids
            if object_exists:
                source = f"object-{item['object_id']}"
            elif domain_exists:
                source = f"domain-{item['domain_id']}"
            elif account_exists:
                source = f"account-{item['account_id']}"
            else:
                source = "legacy-unlinked"
        add_node("request", item["id"], f"Request #{item['id']}")
        if source == "legacy-unlinked" and not any(
            node["id"] == source for node in nodes
        ):
            add_node("legacy", "unlinked", "Legacy / unlinked records")
        edges.append({"source": source, "target": f"request-{item['id']}", "type": "association"})
    active_request_ids = {request["id"] for request in requests}
    for item in attempts:
        add_node("attempt", item["attempt_id"], f"Attempt #{item['attempt_id']}", review_status=item["review_status"])
        if item.get("request_id") in active_request_ids:
            edges.append(
                {
                    "source": f"request-{item['request_id']}",
                    "target": f"attempt-{item['attempt_id']}",
                    "type": "history",
                }
            )
        else:
            add_legacy_group()
            edges.append(
                {
                    "source": "legacy-unlinked",
                    "target": f"attempt-{item['attempt_id']}",
                    "type": "legacy",
                }
            )
    for item in findings:
        add_node("finding", item["finding_id"], item["title"], status=item["status"])
        for attempt_id in (item.get("attempt_ids") or "").split(","):
            if attempt_id.isdigit():
                edges.append(
                    {
                        "source": f"attempt-{attempt_id}",
                        "target": f"finding-{item['finding_id']}",
                        "type": "evidence",
                    }
                )
    return {
        "schema_version": db.get_schema_version(),
        "nodes": nodes,
        "edges": edges,
        "filters": ["domain", "account", "role", "object", "function", "category", "status", "finding"],
    }


@app.get("/api/v1/recon-phases", dependencies=[Auth])
def list_recon_phases() -> list[dict]:
    return [
        {
            "phase_name": phase,
            "answers": db.load_recon_phase_answers(phase),
            "notes": db.get_recon_phase_notes(phase),
        }
        for phase in db.get_recon_phase_names()
    ]


@app.get("/api/v1/recon-phases/{phase_name}", dependencies=[Auth])
def read_recon_phase(phase_name: str) -> dict:
    if phase_name not in db.get_recon_phase_names():
        raise HTTPException(status_code=404, detail="recon phase not found")
    return {
        "phase_name": phase_name,
        "answers": db.load_recon_phase_answers(phase_name),
        "notes": db.get_recon_phase_notes(phase_name),
    }


@app.put(
    "/api/v1/recon-phases/{phase_name}/answers",
    dependencies=[Auth],
)
def save_recon_answer(phase_name: str, payload: ReconAnswerInput) -> dict:
    try:
        db.save_recon_phase_answer(phase_name, payload.question, payload.answer)
    except ValueError as exc:
        raise _service_error(exc) from exc
    return read_recon_phase(phase_name)


@app.delete(
    "/api/v1/recon-phases/{phase_name}/answers",
    status_code=204,
    dependencies=[Auth],
)
def remove_recon_answers(phase_name: str) -> None:
    db.delete_recon_phase_answers(phase_name)


@app.put(
    "/api/v1/recon-phases/{phase_name}/notes",
    dependencies=[Auth],
)
def save_recon_notes(phase_name: str, payload: ReconNotesInput) -> dict:
    try:
        db.save_recon_phase_notes(phase_name, payload.notes)
    except ValueError as exc:
        raise _service_error(exc) from exc
    return read_recon_phase(phase_name)


@app.delete(
    "/api/v1/recon-phases/{phase_name}/notes",
    status_code=204,
    dependencies=[Auth],
)
def remove_recon_notes(phase_name: str) -> None:
    db.delete_recon_phase_notes(phase_name)
