import base64
import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from modules import db
import api

TEST_API_TOKEN = "test-token-for-api-authentication-long"


class VersionTwoDataTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "manual.sqlite"
        self.db_path_patch = patch.object(db, "get_db_path", return_value=self.database)
        self.db_path_patch.start()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def _create_context(self):
        db.init_db()
        account_id = db.save_account("Admin account", role="admin")
        program_id = db.create_program("Test program", "in-scope assets")
        domain_id = db.create_domain(
            program_id,
            "app.example.test",
            "https://app.example.test",
            account_ids=[account_id],
        )
        object_id = db.save_object("Project", account_id)
        function_id = db.save_function("Read project", object_id=object_id)
        request_id = db.add_request(
            "GET /projects/1 HTTP/1.1",
            function_id=function_id,
            domain_id=domain_id,
            account_id=account_id,
        )
        return account_id, program_id, domain_id, object_id, function_id, request_id

    def test_migration_is_repeatable_and_preserves_legacy_request(self):
        with sqlite3.connect(self.database) as conn:
            conn.execute(
                """
                CREATE TABLE requests (
                    id INTEGER PRIMARY KEY,
                    function_id INTEGER,
                    request TEXT NOT NULL,
                    testing_space TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ssrf BOOLEAN DEFAULT 0
                )
                """
            )
            conn.execute(
                "INSERT INTO requests (id, request, testing_space, ssrf) VALUES (7, ?, ?, 1)",
                ("GET /legacy HTTP/1.1", "old notes"),
            )
        db.init_db()
        db.init_db()
        with sqlite3.connect(self.database) as conn:
            row = conn.execute(
                "SELECT request, testing_space, ssrf FROM requests WHERE id = 7"
            ).fetchone()
        self.assertEqual(row, ("GET /legacy HTTP/1.1", "old notes", 1))
        self.assertEqual(db.get_schema_version(), 2)
        self.assertIsNone(db.get_request(7)["function_id"])

    def test_attempt_evidence_is_immutable_and_survives_archival(self):
        account_id, _, _, _, _, request_id = self._create_context()
        category = next(
            item for item in db.get_test_categories() if item["name"] == "idor"
        )
        attempt_id = db.create_request_attempt(
            request_id,
            "GET /projects/2 HTTP/1.1",
            account_id=account_id,
            response_status=403,
            response_headers="HTTP/1.1 403 Forbidden",
            response_body=b"forbidden",
            diff={"path": {"before": "/projects/1", "after": "/projects/2"}},
            category_ids=[category["category_id"]],
            idempotency_key="attempt-retry",
        )
        self.assertEqual(
            db.create_request_attempt(
                request_id,
                "GET /projects/2 HTTP/1.1",
                account_id=account_id,
                response_status=403,
                response_headers="HTTP/1.1 403 Forbidden",
                response_body=b"forbidden",
                diff={"path": {"before": "/projects/1", "after": "/projects/2"}},
                category_ids=[category["category_id"]],
                idempotency_key="attempt-retry",
            ),
            attempt_id,
        )
        with self.assertRaises(ValueError):
            db.update_attempt_annotations(attempt_id, sent_request="changed")
        db.update_attempt_annotations(attempt_id, review_status="needs_review")
        finding_id = db.create_finding(
            "Possible authorization issue",
            status="suspected",
            attempt_ids=[attempt_id],
        )
        db.archive_request(request_id)
        self.assertIsNone(db.get_request(request_id))
        attempt = db.get_request_attempt(attempt_id)
        self.assertEqual(attempt["response_body"], b"forbidden")
        self.assertEqual(attempt["review_status"], "needs_review")
        self.assertEqual(db.get_findings()[0]["finding_id"], finding_id)

    def test_domain_ownership_and_object_parent_are_validated(self):
        account_id, program_id, _, object_id, _, _ = self._create_context()
        other_account_id = db.save_account("Other account")
        with self.assertRaises(ValueError):
            db.create_domain(
                program_id,
                "other.example.test",
                account_ids=[other_account_id + 100],
            )
        with self.assertRaises(ValueError):
            db.save_object("Cross-account child", other_account_id, object_id)
        self.assertIsNotNone(db.get_account(account_id))
        db.archive_object(object_id)
        self.assertEqual(db.get_objects_for_account(account_id), [])
        self.assertTrue(
            all(item["archived_at"] for item in db.get_all_objects())
        )

    def test_api_auth_and_attempt_json_encoding(self):
        account_id, _, domain_id, _, function_id, _ = self._create_context()
        with patch.dict("os.environ", {"MANUAL_FRAMEWORK_API_TOKEN": TEST_API_TOKEN}):
            api.require_api_token(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=TEST_API_TOKEN)
            )
            with patch.dict("os.environ", {"MANUAL_FRAMEWORK_API_TOKEN": "short"}):
                with self.assertRaises(HTTPException) as missing_configuration:
                    api.require_api_token(
                        HTTPAuthorizationCredentials(
                            scheme="Bearer", credentials="short"
                        )
                    )
                self.assertEqual(missing_configuration.exception.status_code, 503)
            with self.assertRaises(HTTPException) as error:
                api.require_api_token(
                    HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong")
                )
            self.assertEqual(error.exception.status_code, 401)

        request = api.create_request(
            api.RequestInput(
                request="GET /items/1 HTTP/1.1",
                function_id=function_id,
                domain_id=domain_id,
                account_id=account_id,
            )
        )
        payload = api.AttemptInput(
            request_id=request["id"],
            sent_request="GET /items/2 HTTP/1.1",
            response_body_base64=base64.b64encode(b"response").decode("ascii"),
        )
        stored = api.create_attempt(request["id"], payload, None)
        self.assertEqual(
            base64.b64decode(stored["response_body_base64"]),
            b"response",
        )

    def test_http_routes_require_auth_and_persist_captured_evidence(self):
        db.init_db()

        def call(method, path, payload=None, token=TEST_API_TOKEN):
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            headers = [(b"content-type", b"application/json")]
            if token:
                headers.append(
                    (b"authorization", ("Bearer " + token).encode("ascii"))
                )
            messages = []
            sent = False

            async def receive():
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                messages.append(message)

            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": path,
                "raw_path": path.encode("ascii"),
                "query_string": b"",
                "root_path": "",
                "headers": headers,
                "client": ("127.0.0.1", 1),
                "server": ("127.0.0.1", 80),
            }
            asyncio.run(api.app(scope, receive, send))
            start = next(item for item in messages if item["type"] == "http.response.start")
            response_body = b"".join(
                item.get("body", b"")
                for item in messages
                if item["type"] == "http.response.body"
            )
            return start["status"], json.loads(response_body) if response_body else None

        with patch.dict(os.environ, {"MANUAL_FRAMEWORK_API_TOKEN": TEST_API_TOKEN}):
            status, _ = call("GET", "/api/v1/programs", token="")
            self.assertEqual(status, 401)
            _, account = call(
                "POST",
                "/api/v1/accounts",
                {"account_name": "API tester", "role": "member"},
            )
            self.assertNotIn("password", account)
            _, program = call(
                "POST",
                "/api/v1/programs",
                {"name": "API program", "scope_notes": "authorized"},
            )
            _, domain = call(
                "POST",
                "/api/v1/domains",
                {
                    "program_id": program["program_id"],
                    "name": "api.example.test",
                    "account_ids": [account["id"]],
                },
            )
            _, request = call(
                "POST",
                "/api/v1/requests",
                {
                    "request": "GET /items/1 HTTP/1.1",
                    "domain_id": domain["domain_id"],
                    "account_id": account["id"],
                },
            )
            _, attempt = call(
                "POST",
                f"/api/v1/requests/{request['id']}/attempts",
                {
                    "request_id": request["id"],
                    "sent_request": "GET /items/2 HTTP/1.1",
                    "response_status": 403,
                    "response_body_base64": base64.b64encode(b"denied").decode("ascii"),
                },
            )
            _, saved = call("GET", f"/api/v1/attempts/{attempt['attempt_id']}")
            self.assertEqual(
                base64.b64decode(saved["response_body_base64"]),
                b"denied",
            )
            self.assertEqual(saved["sent_request"], "GET /items/2 HTTP/1.1")


if __name__ == "__main__":
    unittest.main()
