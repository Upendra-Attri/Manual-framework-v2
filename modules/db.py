import sqlite3
from pathlib import Path
import re
import json

DB_NAME = "manual_frameworks.db"
BASE_REQUEST_COLUMNS = {
    "id",
    "function_id",
    "object_id",
    "domain_id",
    "account_id",
    "request",
    "testing_space",
    "created_at",
    "archived_at",
}
V1_REQUEST_CHECKLIST_COLUMNS = {
    "ssrf",
    "idor",
    "xss",
    "sqli",
    "csrf",
    "rce",
    "lfi",
    "open_redirect",
}
SCHEMA_VERSION = 2
BUILT_IN_TEST_CATEGORIES = (
    "ssrf",
    "idor",
    "xss",
    "sqli",
    "csrf",
    "rce",
    "lfi",
    "open_redirect",
)


def _quote_identifier(identifier: str) -> str:
    identifier = identifier.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
        raise ValueError("Names may contain only letters, numbers, and underscores")
    return f'"{identifier}"'


def get_db_path() -> Path:
    return (Path(__file__).resolve().parent.parent / DB_NAME).resolve()


def init_db() -> Path:
    db_path = get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_id INTEGER,
                request TEXT NOT NULL,
                ssrf BOOLEAN DEFAULT 0,
                idor BOOLEAN DEFAULT 0,
                xss BOOLEAN DEFAULT 0,
                sqli BOOLEAN DEFAULT 0,
                csrf BOOLEAN DEFAULT 0,
                rce BOOLEAN DEFAULT 0,
                lfi BOOLEAN DEFAULT 0,
                open_redirect BOOLEAN DEFAULT 0,
                testing_space TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS recon_phase_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase_name TEXT NOT NULL UNIQUE,
                notes TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS recon_phase_answers (
                phase_name TEXT NOT NULL,
                question TEXT NOT NULL,
                answer TEXT,
                PRIMARY KEY (phase_name, question)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_name TEXT NOT NULL,
                email TEXT,
                username TEXT,
                password TEXT,
                role TEXT,
                org TEXT,
                account_type TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        account_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()
        }
        if "archived_at" not in account_columns:
            conn.execute("ALTER TABLE accounts ADD COLUMN archived_at TIMESTAMP")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS objects (
                object_id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_name TEXT NOT NULL,
                parent_object_id INTEGER,
                account_id INTEGER NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (parent_object_id) REFERENCES objects(object_id) ON DELETE CASCADE,
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
            """
        )
        object_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(objects)").fetchall()
        }
        if "archived_at" not in object_columns:
            conn.execute("ALTER TABLE objects ADD COLUMN archived_at TIMESTAMP")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS functions (
                function_id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_name TEXT NOT NULL,
                function_boundries_created TEXT,
                notes TEXT,
                object_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (object_id) REFERENCES objects(object_id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS function_objects (
                function_id INTEGER NOT NULL,
                object_id INTEGER NOT NULL,
                PRIMARY KEY (function_id, object_id),
                FOREIGN KEY (function_id) REFERENCES functions(function_id) ON DELETE CASCADE,
                FOREIGN KEY (object_id) REFERENCES objects(object_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO function_objects (function_id, object_id)
            SELECT function_id, object_id
            FROM functions
            WHERE object_id IS NOT NULL
            """
        )
        request_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()
        }
        if "function_id" not in request_columns:
            conn.execute("ALTER TABLE requests ADD COLUMN function_id INTEGER")
        for column_name in V1_REQUEST_CHECKLIST_COLUMNS - request_columns:
            conn.execute(
                f"ALTER TABLE requests ADD COLUMN {_quote_identifier(column_name)} BOOLEAN DEFAULT 0"
            )
        if "domain_id" not in request_columns:
            conn.execute("ALTER TABLE requests ADD COLUMN domain_id INTEGER")
        if "account_id" not in request_columns:
            conn.execute("ALTER TABLE requests ADD COLUMN account_id INTEGER")
        if "object_id" not in request_columns:
            conn.execute("ALTER TABLE requests ADD COLUMN object_id INTEGER")
        if "archived_at" not in request_columns:
            conn.execute("ALTER TABLE requests ADD COLUMN archived_at TIMESTAMP")
        function_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(functions)").fetchall()
        }
        if "archived_at" not in function_columns:
            conn.execute("ALTER TABLE functions ADD COLUMN archived_at TIMESTAMP")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS programs (
                program_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_notes TEXT NOT NULL DEFAULT '',
                policy_url TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                archived_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domains (
                domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                archived_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (program_id, name),
                FOREIGN KEY (program_id) REFERENCES programs(program_id) ON DELETE RESTRICT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_domains (
                account_id INTEGER NOT NULL,
                domain_id INTEGER NOT NULL,
                PRIMARY KEY (account_id, domain_id),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
                FOREIGN KEY (domain_id) REFERENCES domains(domain_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS test_categories (
                category_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                built_in BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER,
                request_label TEXT NOT NULL DEFAULT '',
                account_id INTEGER,
                baseline_request TEXT NOT NULL DEFAULT '',
                sent_request TEXT NOT NULL,
                response_status INTEGER,
                response_headers TEXT NOT NULL DEFAULT '',
                response_body BLOB,
                response_body_encoding TEXT NOT NULL DEFAULT 'utf-8',
                diff_json TEXT NOT NULL DEFAULT '{}',
                notes TEXT NOT NULL DEFAULT '',
                expected_behavior TEXT NOT NULL DEFAULT '',
                observed_behavior TEXT NOT NULL DEFAULT '',
                review_status TEXT NOT NULL DEFAULT 'unreviewed',
                idempotency_key TEXT UNIQUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE SET NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempt_categories (
                attempt_id INTEGER NOT NULL,
                category_id INTEGER NOT NULL,
                PRIMARY KEY (attempt_id, category_id),
                FOREIGN KEY (attempt_id) REFERENCES request_attempts(attempt_id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES test_categories(category_id) ON DELETE RESTRICT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'suspected',
                severity TEXT NOT NULL DEFAULT '',
                impact TEXT NOT NULL DEFAULT '',
                report_notes TEXT NOT NULL DEFAULT '',
                archived_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_attempts (
                finding_id INTEGER NOT NULL,
                attempt_id INTEGER NOT NULL,
                PRIMARY KEY (finding_id, attempt_id),
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
                FOREIGN KEY (attempt_id) REFERENCES request_attempts(attempt_id) ON DELETE RESTRICT
            )
            """
        )
        conn.executemany(
            "INSERT OR IGNORE INTO test_categories (name, built_in) VALUES (?, 1)",
            [(name,) for name in BUILT_IN_TEST_CATEGORIES],
        )
        for column_name in sorted(
            {
                row[1]
                for row in conn.execute("PRAGMA table_info(requests)").fetchall()
                if row[1] not in BASE_REQUEST_COLUMNS
            }
        ):
            conn.execute(
                "INSERT OR IGNORE INTO test_categories (name, built_in) VALUES (?, ?)",
                (column_name, int(column_name in BUILT_IN_TEST_CATEGORIES)),
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        conn.commit()

    return db_path


def get_schema_version() -> int:
    with sqlite3.connect(get_db_path()) as conn:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


def create_program(
    name: str,
    scope_notes: str = "",
    policy_url: str = "",
    status: str = "active",
) -> int:
    name = name.strip()
    if not name:
        raise ValueError("program name cannot be empty")
    if status not in {"active", "paused", "completed"}:
        raise ValueError("status must be active, paused, or completed")
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            "INSERT INTO programs (name, scope_notes, policy_url, status) VALUES (?, ?, ?, ?)",
            (name, scope_notes, policy_url, status),
        )
        return int(cursor.lastrowid)


def update_program(
    program_id: int,
    name: str,
    scope_notes: str,
    policy_url: str,
    status: str,
) -> None:
    name = name.strip()
    if not name:
        raise ValueError("program name cannot be empty")
    if status not in {"active", "paused", "completed"}:
        raise ValueError("status must be active, paused, or completed")
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE programs
            SET name = ?, scope_notes = ?, policy_url = ?, status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE program_id = ? AND archived_at IS NULL
            """,
            (name, scope_notes, policy_url, status, program_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("program not found")


def archive_program(program_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE programs SET archived_at = CURRENT_TIMESTAMP, status = 'archived',
                updated_at = CURRENT_TIMESTAMP
            WHERE program_id = ? AND archived_at IS NULL
            """,
            (program_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("program not found")


def get_programs(include_archived: bool = False) -> list[dict]:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        sql = "SELECT * FROM programs"
        if not include_archived:
            sql += " WHERE archived_at IS NULL"
        rows = conn.execute(sql + " ORDER BY name COLLATE NOCASE, program_id").fetchall()
    return [dict(row) for row in rows]


def create_domain(
    program_id: int,
    name: str,
    base_url: str = "",
    notes: str = "",
    account_ids: list[int] | None = None,
    status: str = "active",
) -> int:
    name = name.strip()
    if not name:
        raise ValueError("domain name cannot be empty")
    if status not in {"active", "paused", "completed"}:
        raise ValueError("status must be active, paused, or completed")
    with sqlite3.connect(get_db_path()) as conn:
        if not conn.execute(
            "SELECT 1 FROM programs WHERE program_id = ? AND archived_at IS NULL",
            (program_id,),
        ).fetchone():
            raise ValueError("program not found")
        cursor = conn.execute(
            "INSERT INTO domains (program_id, name, base_url, notes, status) VALUES (?, ?, ?, ?, ?)",
            (program_id, name, base_url, notes, status),
        )
        domain_id = int(cursor.lastrowid)
        _link_domain_accounts(conn, domain_id, account_ids or [])
        return domain_id


def _link_domain_accounts(
    conn: sqlite3.Connection, domain_id: int, account_ids: list[int]
) -> None:
    normalized_ids = sorted(set(account_ids))
    if normalized_ids:
        placeholders = ", ".join("?" for _ in normalized_ids)
        count = conn.execute(
            f"SELECT COUNT(*) FROM accounts WHERE archived_at IS NULL AND id IN ({placeholders})",
            normalized_ids,
        ).fetchone()[0]
        if count != len(normalized_ids):
            raise ValueError("one or more accounts do not exist")
    conn.execute("DELETE FROM account_domains WHERE domain_id = ?", (domain_id,))
    conn.executemany(
        "INSERT INTO account_domains (account_id, domain_id) VALUES (?, ?)",
        [(account_id, domain_id) for account_id in normalized_ids],
    )


def update_domain(
    domain_id: int,
    name: str,
    base_url: str,
    notes: str,
    status: str,
    account_ids: list[int],
) -> None:
    name = name.strip()
    if not name:
        raise ValueError("domain name cannot be empty")
    if status not in {"active", "paused", "completed"}:
        raise ValueError("status must be active, paused, or completed")
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE domains SET name = ?, base_url = ?, notes = ?, status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE domain_id = ? AND archived_at IS NULL
            """,
            (name, base_url, notes, status, domain_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("domain not found")
        _link_domain_accounts(conn, domain_id, account_ids)


def archive_domain(domain_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE domains SET archived_at = CURRENT_TIMESTAMP, status = 'archived',
                updated_at = CURRENT_TIMESTAMP
            WHERE domain_id = ? AND archived_at IS NULL
            """,
            (domain_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("domain not found")


def get_domains(include_archived: bool = False) -> list[dict]:
    query = """
        SELECT d.*, p.name AS program_name,
            GROUP_CONCAT(DISTINCT a.id) AS account_ids
        FROM domains d
        JOIN programs p ON p.program_id = d.program_id
        LEFT JOIN account_domains ad ON ad.domain_id = d.domain_id
        LEFT JOIN accounts a ON a.id = ad.account_id AND a.archived_at IS NULL
    """
    if not include_archived:
        query += " WHERE d.archived_at IS NULL AND p.archived_at IS NULL"
    query += " GROUP BY d.domain_id ORDER BY p.name COLLATE NOCASE, d.name COLLATE NOCASE"
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]


def get_test_categories() -> list[dict]:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM test_categories ORDER BY name COLLATE NOCASE, category_id"
        ).fetchall()
    return [dict(row) for row in rows]


def create_test_category(name: str) -> int:
    name = name.strip()
    if not name:
        raise ValueError("category name cannot be empty")
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            "INSERT INTO test_categories (name, built_in) VALUES (?, 0)", (name,)
        )
        return int(cursor.lastrowid)


def delete_test_category(category_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.execute(
            "DELETE FROM test_categories WHERE category_id = ? AND built_in = 0",
            (category_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("custom category not found")


def create_request_attempt(
    request_id: int,
    sent_request: str,
    baseline_request: str = "",
    account_id: int | None = None,
    response_status: int | None = None,
    response_headers: str = "",
    response_body: bytes | None = None,
    response_body_encoding: str = "utf-8",
    diff: dict | None = None,
    notes: str = "",
    expected_behavior: str = "",
    observed_behavior: str = "",
    category_ids: list[int] | None = None,
    idempotency_key: str | None = None,
) -> int:
    if not sent_request:
        raise ValueError("sent_request cannot be empty")
    category_ids = sorted(set(category_ids or []))
    serialized_diff = json.dumps(diff or {}, sort_keys=True)
    with sqlite3.connect(get_db_path()) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        request = conn.execute(
            """
            SELECT request, domain_id, account_id
            FROM requests WHERE id = ? AND archived_at IS NULL
            """,
            (request_id,),
        ).fetchone()
        if request is None:
            raise ValueError("request definition not found")
        if account_id is not None:
            if not conn.execute(
                "SELECT 1 FROM accounts WHERE id = ? AND archived_at IS NULL",
                (account_id,),
            ).fetchone():
                raise ValueError("account not found")
            if request[2] is not None and request[2] != account_id:
                raise ValueError("attempt account does not match the request definition")
            if request[1] is not None and not conn.execute(
                "SELECT 1 FROM account_domains WHERE account_id = ? AND domain_id = ?",
                (account_id, request[1]),
            ).fetchone():
                raise ValueError("attempt account is not associated with the request domain")
        if category_ids:
            placeholders = ", ".join("?" for _ in category_ids)
            count = conn.execute(
                f"SELECT COUNT(*) FROM test_categories WHERE category_id IN ({placeholders})",
                category_ids,
            ).fetchone()[0]
            if count != len(category_ids):
                raise ValueError("one or more test categories do not exist")
        values = (
            request_id,
            request[0] or "",
            account_id,
            baseline_request,
            sent_request,
            response_status,
            response_headers,
            response_body,
            response_body_encoding,
            serialized_diff,
            notes,
            expected_behavior,
            observed_behavior,
            idempotency_key,
        )
        try:
            cursor = conn.execute(
                """
                INSERT INTO request_attempts (
                    request_id, request_label, account_id, baseline_request,
                    sent_request, response_status, response_headers, response_body,
                    response_body_encoding, diff_json, notes, expected_behavior,
                    observed_behavior, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            attempt_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            if not idempotency_key:
                raise
            row = conn.execute(
                """
                SELECT attempt_id, request_id, account_id, baseline_request,
                    sent_request, response_status, response_headers, response_body,
                    response_body_encoding, diff_json, notes, expected_behavior,
                    observed_behavior
                FROM request_attempts WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            duplicate_categories = (
                conn.execute(
                    "SELECT category_id FROM attempt_categories WHERE attempt_id = ? ORDER BY category_id",
                    (row[0],),
                ).fetchall()
                if row is not None
                else []
            )
            expected_values = (
                request_id,
                account_id,
                baseline_request,
                sent_request,
                response_status,
                response_headers,
                response_body,
                response_body_encoding,
                serialized_diff,
                notes,
                expected_behavior,
                observed_behavior,
            )
            if (
                row is None
                or tuple(row[1:]) != expected_values
                or [item[0] for item in duplicate_categories] != category_ids
            ):
                raise ValueError("idempotency key was already used for a different attempt") from exc
            return int(row[0])
        conn.executemany(
            "INSERT INTO attempt_categories (attempt_id, category_id) VALUES (?, ?)",
            [(attempt_id, category_id) for category_id in category_ids],
        )
        return attempt_id


def get_request_attempts(request_id: int) -> list[dict]:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT a.*, GROUP_CONCAT(c.name) AS categories
            FROM request_attempts a
            LEFT JOIN attempt_categories ac ON ac.attempt_id = a.attempt_id
            LEFT JOIN test_categories c ON c.category_id = ac.category_id
            WHERE a.request_id = ?
            GROUP BY a.attempt_id
            ORDER BY a.created_at, a.attempt_id
            """,
            (request_id,),
        ).fetchall()
    result = [dict(row) for row in rows]
    for attempt in result:
        attempt["diff"] = json.loads(attempt.pop("diff_json") or "{}")
    return result


def get_all_request_attempts() -> list[dict]:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT a.*, GROUP_CONCAT(c.name) AS categories
            FROM request_attempts a
            LEFT JOIN attempt_categories ac ON ac.attempt_id = a.attempt_id
            LEFT JOIN test_categories c ON c.category_id = ac.category_id
            GROUP BY a.attempt_id
            ORDER BY a.created_at, a.attempt_id
            """
        ).fetchall()
    result = [dict(row) for row in rows]
    for attempt in result:
        attempt["diff"] = json.loads(attempt.pop("diff_json") or "{}")
    return result


def get_request_attempt(attempt_id: int) -> dict | None:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT a.*, GROUP_CONCAT(c.name) AS categories
            FROM request_attempts a
            LEFT JOIN attempt_categories ac ON ac.attempt_id = a.attempt_id
            LEFT JOIN test_categories c ON c.category_id = ac.category_id
            WHERE a.attempt_id = ?
            GROUP BY a.attempt_id
            """,
            (attempt_id,),
        ).fetchone()
    if row is None:
        return None
    attempt = dict(row)
    attempt["diff"] = json.loads(attempt.pop("diff_json") or "{}")
    return attempt


def update_attempt_annotations(attempt_id: int, **annotations) -> None:
    allowed = {"notes", "expected_behavior", "observed_behavior", "review_status"}
    if not annotations or annotations.keys() - allowed:
        raise ValueError("only notes, expected_behavior, observed_behavior, and review_status can be updated")
    if annotations.get("review_status") not in (
        None,
        "unreviewed",
        "needs_review",
        "reviewed",
    ):
        raise ValueError("review_status must be unreviewed, needs_review, or reviewed")
    assignments = ", ".join(f"{key} = ?" for key in annotations)
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            f"UPDATE request_attempts SET {assignments} WHERE attempt_id = ?",
            (*annotations.values(), attempt_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("attempt not found")


def link_attempt_category(attempt_id: int, category_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        try:
            conn.execute(
                "INSERT INTO attempt_categories (attempt_id, category_id) VALUES (?, ?)",
                (attempt_id, category_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("attempt or category not found, or category already linked") from exc


def unlink_attempt_category(attempt_id: int, category_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            "DELETE FROM attempt_categories WHERE attempt_id = ? AND category_id = ?",
            (attempt_id, category_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("attempt category link not found")


def create_finding(
    title: str,
    description: str = "",
    status: str = "suspected",
    severity: str = "",
    impact: str = "",
    report_notes: str = "",
    attempt_ids: list[int] | None = None,
) -> int:
    title = title.strip()
    if not title:
        raise ValueError("finding title cannot be empty")
    if status not in {"suspected", "confirmed", "closed", "rejected"}:
        raise ValueError("invalid finding status")
    attempt_ids = sorted(set(attempt_ids or []))
    with sqlite3.connect(get_db_path()) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.execute(
            """
            INSERT INTO findings (title, description, status, severity, impact, report_notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, description, status, severity, impact, report_notes),
        )
        finding_id = int(cursor.lastrowid)
        for attempt_id in attempt_ids:
            if not conn.execute(
                "SELECT 1 FROM request_attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone():
                raise ValueError(f"attempt {attempt_id} not found")
            conn.execute(
                "INSERT INTO finding_attempts (finding_id, attempt_id) VALUES (?, ?)",
                (finding_id, attempt_id),
            )
        return finding_id


def get_findings(include_archived: bool = False) -> list[dict]:
    query = """
        SELECT f.*, GROUP_CONCAT(fa.attempt_id) AS attempt_ids
        FROM findings f LEFT JOIN finding_attempts fa ON fa.finding_id = f.finding_id
    """
    if not include_archived:
        query += " WHERE f.archived_at IS NULL"
    query += " GROUP BY f.finding_id ORDER BY f.created_at DESC, f.finding_id DESC"
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchall()
    return [dict(row) for row in rows]


def update_finding(finding_id: int, **fields) -> None:
    allowed = {"title", "description", "status", "severity", "impact", "report_notes"}
    if not fields or fields.keys() - allowed:
        raise ValueError("invalid finding fields")
    if "title" in fields and not fields["title"].strip():
        raise ValueError("finding title cannot be empty")
    if fields.get("status") not in (None, "suspected", "confirmed", "closed", "rejected"):
        raise ValueError("invalid finding status")
    assignments = ", ".join(f"{key} = ?" for key in fields)
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            f"""
            UPDATE findings SET {assignments}, updated_at = CURRENT_TIMESTAMP
            WHERE finding_id = ? AND archived_at IS NULL
            """,
            (*fields.values(), finding_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("finding not found")


def archive_finding(finding_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE findings SET archived_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE finding_id = ? AND archived_at IS NULL
            """,
            (finding_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("finding not found")


def add_request(
    request: str,
    testing_space: str = "",
    function_id: int | None = None,
    domain_id: int | None = None,
    account_id: int | None = None,
    object_id: int | None = None,
    **vulns,
) -> int:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        class_columns = [
            row[1]
            for row in conn.execute("PRAGMA table_info(requests)").fetchall()
            if row[1] not in BASE_REQUEST_COLUMNS
        ]
        insert_columns = [
            "function_id",
            "object_id",
            "domain_id",
            "account_id",
            "request",
            *class_columns,
            "testing_space",
        ]
        values = [
            function_id,
            object_id,
            domain_id,
            account_id,
            request,
            *(1 if bool(vulns.get(column, False)) else 0 for column in class_columns),
            testing_space,
        ]
        quoted_columns = ", ".join(_quote_identifier(column) for column in insert_columns)
        placeholders = ", ".join("?" for _ in insert_columns)
        cursor = conn.execute(
            f"INSERT INTO requests ({quoted_columns}) VALUES ({placeholders})",
            values,
        )
        conn.commit()
        return cursor.lastrowid


def get_all_requests() -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM requests WHERE archived_at IS NULL ORDER BY id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_request(request_id: int) -> dict | None:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM requests WHERE id = ? AND archived_at IS NULL", (request_id,)
        ).fetchone()
    return dict(row) if row else None


def get_requests_for_function(function_id: int) -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM requests WHERE function_id = ? AND archived_at IS NULL ORDER BY id ASC",
            (function_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_request_class_columns() -> list[str]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()]
    return [column for column in columns if column not in BASE_REQUEST_COLUMNS]


def delete_request(request_id: int) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        has_history = conn.execute(
            "SELECT 1 FROM request_attempts WHERE request_id = ? LIMIT 1",
            (request_id,),
        ).fetchone()
        if has_history:
            conn.execute(
                """
                UPDATE requests SET archived_at = CURRENT_TIMESTAMP
                WHERE id = ? AND archived_at IS NULL
                """,
                (request_id,),
            )
        else:
            conn.execute("DELETE FROM requests WHERE id = ?", (request_id,))
        conn.commit()


def update_testing_space(request_id: int, testing_space: str) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE requests SET testing_space = ? WHERE id = ?",
            (testing_space, request_id),
        )
        conn.commit()


def update_request(request_id: int, request: str, testing_space: str) -> None:
    request = request.strip()
    if not request:
        raise ValueError("request cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE requests SET request = ?, testing_space = ? WHERE id = ?",
            (request, testing_space, request_id),
        )
        conn.commit()


def update_request_context(
    request_id: int,
    function_id: int | None,
    domain_id: int | None,
    account_id: int | None,
    object_id: int | None,
    request: str | None = None,
    testing_space: str | None = None,
) -> None:
    if request is not None and not request.strip():
        raise ValueError("request cannot be empty")
    with sqlite3.connect(get_db_path()) as conn:
        if not conn.execute(
            "SELECT 1 FROM requests WHERE id = ? AND archived_at IS NULL",
            (request_id,),
        ).fetchone():
            raise ValueError("request not found")
        if function_id is not None and not conn.execute(
            "SELECT 1 FROM functions WHERE function_id = ? AND archived_at IS NULL",
            (function_id,),
        ).fetchone():
            raise ValueError("function not found")
        if domain_id is not None and not conn.execute(
            "SELECT 1 FROM domains WHERE domain_id = ? AND archived_at IS NULL",
            (domain_id,),
        ).fetchone():
            raise ValueError("domain not found")
        if account_id is not None and not conn.execute(
            "SELECT 1 FROM accounts WHERE id = ? AND archived_at IS NULL",
            (account_id,),
        ).fetchone():
            raise ValueError("account not found")
        if object_id is not None:
            object_row = conn.execute(
                "SELECT account_id FROM objects WHERE object_id = ? AND archived_at IS NULL",
                (object_id,),
            ).fetchone()
            if object_row is None:
                raise ValueError("object not found")
            if account_id is not None and object_row[0] != account_id:
                raise ValueError("object must belong to the selected account")
            if account_id is None:
                account_id = object_row[0]
        if domain_id is not None and account_id is not None and not conn.execute(
            "SELECT 1 FROM account_domains WHERE account_id = ? AND domain_id = ?",
            (account_id, domain_id),
        ).fetchone():
            raise ValueError("account is not associated with the selected domain")
        if request is None:
            conn.execute(
                """
                UPDATE requests SET function_id = ?, domain_id = ?, account_id = ?,
                    object_id = ? WHERE id = ?
                """,
                (function_id, domain_id, account_id, object_id, request_id),
            )
        else:
            conn.execute(
                """
                UPDATE requests SET request = ?, testing_space = ?, function_id = ?,
                    domain_id = ?, account_id = ?, object_id = ? WHERE id = ?
                """,
                (
                    request.strip(),
                    testing_space or "",
                    function_id,
                    domain_id,
                    account_id,
                    object_id,
                    request_id,
                ),
            )


def update_test_space(request_id: int, testing_space: str) -> None:
    update_testing_space(request_id, testing_space)


def update_vuln(request_id: int, vuln_name: str, value: int | bool = 1) -> None:
    vuln_name = vuln_name.strip()
    if not vuln_name:
        raise ValueError("vuln_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()
        }

        quoted_name = _quote_identifier(vuln_name)
        if vuln_name not in existing_columns:
            conn.execute(f"ALTER TABLE requests ADD COLUMN {quoted_name} BOOLEAN DEFAULT 0")

        conn.execute(
            f"UPDATE requests SET {quoted_name} = ? WHERE id = ?",
            (1 if bool(value) else 0, request_id),
        )
        conn.commit()


def update_ssrf(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "ssrf", value)


def update_idor(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "idor", value)


def update_xss(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "xss", value)


def update_sqli(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "sqli", value)


def update_csrf(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "csrf", value)


def update_rce(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "rce", value)


def update_lfi(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "lfi", value)


def update_open_redirect(request_id: int, value: int | bool = 1) -> None:
    update_vuln(request_id, "open_redirect", value)


def add_vuln_column(column_name: str, default_value: int = 0) -> None:
    column_name = column_name.strip()
    if not column_name:
        raise ValueError("column_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()
        }
        quoted_name = _quote_identifier(column_name)
        if column_name not in existing_columns:
            conn.execute(
                f"ALTER TABLE requests ADD COLUMN {quoted_name} BOOLEAN DEFAULT {int(bool(default_value))}"
            )
        conn.commit()


def delete_vuln_column(column_name: str) -> None:
    if column_name in BASE_REQUEST_COLUMNS:
        raise ValueError("Built-in request fields cannot be deleted")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()
        }
        if column_name not in existing_columns:
            return
        conn.execute(f"ALTER TABLE requests DROP COLUMN {_quote_identifier(column_name)}")
        conn.commit()


def delete_account(account_id: int) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()


def delete_recon_phase_answers(phase_name: str) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM recon_phase_answers WHERE phase_name = ?", (phase_name,))
        conn.commit()


def save_recon_phase_notes(phase_name: str, notes: str) -> None:
    phase_name = phase_name.strip()
    if not phase_name:
        raise ValueError("phase_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO recon_phase_notes (phase_name, notes)
            VALUES (?, ?)
            ON CONFLICT(phase_name)
            DO UPDATE SET notes = excluded.notes,
                         updated_at = CURRENT_TIMESTAMP
            """,
            (phase_name, notes),
        )
        conn.commit()


def delete_recon_phase_notes(phase_name: str) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "DELETE FROM recon_phase_notes WHERE phase_name = ?",
            (phase_name.strip(),),
        )
        conn.commit()


def get_recon_phase_notes(phase_name: str) -> str:
    phase_name = phase_name.strip()
    if not phase_name:
        raise ValueError("phase_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT notes FROM recon_phase_notes WHERE phase_name = ?",
            (phase_name,),
        ).fetchone()
    return row[0] if row and row[0] is not None else ""


def get_recon_phase_names() -> list[str]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT phase_name FROM recon_phase_notes
            UNION
            SELECT phase_name FROM recon_phase_answers
            ORDER BY phase_name ASC
            """
        ).fetchall()
    return [row[0] for row in rows]


def save_recon_phase_answer(phase_name: str, question: str, answer: str) -> None:
    phase_name = phase_name.strip()
    question = question.strip()
    if not phase_name or not question:
        raise ValueError("phase_name and question cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO recon_phase_answers (phase_name, question, answer)
            VALUES (?, ?, ?)
            ON CONFLICT(phase_name, question)
            DO UPDATE SET answer = excluded.answer
            """,
            (phase_name, question, answer or ""),
        )
        conn.commit()


def load_recon_phase_answers(phase_name: str) -> dict[str, str]:
    phase_name = phase_name.strip()
    if not phase_name:
        raise ValueError("phase_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT question, answer FROM recon_phase_answers WHERE phase_name = ? ORDER BY question ASC",
            (phase_name,),
        ).fetchall()

    return {question: answer for question, answer in rows}


def save_account(
    account_name: str,
    email: str = "",
    username: str = "",
    password: str = "",
    role: str = "",
    org: str = "",
    account_type: str = "",
    notes: str = "",
) -> int:
    account_name = account_name.strip()
    if not account_name:
        raise ValueError("account_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO accounts (
                account_name,
                email,
                username,
                password,
                role,
                org,
                account_type,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_name,
                email,
                username,
                password,
                role,
                org,
                account_type,
                notes,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_all_accounts() -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM accounts WHERE archived_at IS NULL ORDER BY id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_account(account_id: int) -> dict | None:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND archived_at IS NULL",
            (account_id,),
        ).fetchone()
    return dict(row) if row else None


def archive_account(account_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE accounts SET archived_at = CURRENT_TIMESTAMP
            WHERE id = ? AND archived_at IS NULL
            """,
            (account_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("account not found")


def archive_function(function_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE functions SET archived_at = CURRENT_TIMESTAMP
            WHERE function_id = ? AND archived_at IS NULL
            """,
            (function_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("function not found")


def archive_request(request_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            UPDATE requests SET archived_at = CURRENT_TIMESTAMP
            WHERE id = ? AND archived_at IS NULL
            """,
            (request_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("request not found")


def update_account(
    account_id: int,
    account_name: str,
    email: str = "",
    username: str = "",
    password: str = "",
    role: str = "",
    org: str = "",
    account_type: str = "",
    notes: str = "",
) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE accounts
            SET account_name = ?,
                email = ?,
                username = ?,
                password = ?,
                role = ?,
                org = ?,
                account_type = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                account_name,
                email,
                username,
                password,
                role,
                org,
                account_type,
                notes,
                account_id,
            ),
        )
        conn.commit()


def save_object(
    object_name: str,
    account_id: int,
    parent_object_id: int | None = None,
    notes: str = "",
) -> int:
    object_name = object_name.strip()
    if not object_name:
        raise ValueError("object_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        if not conn.execute(
            "SELECT 1 FROM accounts WHERE id = ? AND archived_at IS NULL",
            (account_id,),
        ).fetchone():
            raise ValueError("account not found")
        if parent_object_id is not None:
            parent = conn.execute(
                "SELECT account_id FROM objects WHERE object_id = ? AND archived_at IS NULL",
                (parent_object_id,),
            ).fetchone()
            if parent is None:
                raise ValueError("parent object not found")
            if parent[0] != account_id:
                raise ValueError("parent object must belong to the same account")
        cursor = conn.execute(
            """
            INSERT INTO objects (object_name, parent_object_id, account_id, notes)
            VALUES (?, ?, ?, ?)
            """,
            (object_name, parent_object_id, account_id, notes),
        )
        conn.commit()
        return cursor.lastrowid


def get_objects_for_account(account_id: int) -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT object_id, object_name, parent_object_id, account_id, notes, created_at
            FROM objects
            WHERE account_id = ? AND archived_at IS NULL
            ORDER BY object_name COLLATE NOCASE ASC, object_id ASC
            """,
            (account_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_objects() -> list[dict]:
    with sqlite3.connect(get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT o.object_id, o.object_name, o.parent_object_id, o.account_id,
                o.notes, o.created_at, o.archived_at, a.account_name,
                a.archived_at AS account_archived_at
            FROM objects o
            LEFT JOIN accounts a ON a.id = o.account_id
            ORDER BY o.object_id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def update_object(
    object_id: int,
    object_name: str,
    parent_object_id: int | None,
    notes: str = "",
) -> None:
    object_name = object_name.strip()
    if not object_name:
        raise ValueError("object_name cannot be empty")
    if parent_object_id == object_id:
        raise ValueError("An object cannot be its own parent")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        current = conn.execute(
            "SELECT account_id FROM objects WHERE object_id = ? AND archived_at IS NULL",
            (object_id,),
        ).fetchone()
        if current is None:
            raise ValueError("object not found")
        if parent_object_id is not None:
            current_parent_id = parent_object_id
            visited_ids = {object_id}
            while current_parent_id is not None:
                if current_parent_id in visited_ids:
                    raise ValueError("An object cannot be placed under its own descendant")
                visited_ids.add(current_parent_id)
                row = conn.execute(
                    "SELECT parent_object_id FROM objects WHERE object_id = ? AND archived_at IS NULL",
                    (current_parent_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("The selected parent object does not exist")
                parent_account = conn.execute(
                    "SELECT account_id FROM objects WHERE object_id = ? AND archived_at IS NULL",
                    (current_parent_id,),
                ).fetchone()
                if parent_account is None or parent_account[0] != current[0]:
                    raise ValueError("parent object must belong to the same account")
                current_parent_id = row[0]
        conn.execute(
            """
            UPDATE objects
            SET object_name = ?, parent_object_id = ?, notes = ?
            WHERE object_id = ?
            """,
            (object_name, parent_object_id, notes, object_id),
        )
        conn.commit()


def delete_object(object_id: int) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM objects WHERE object_id = ?", (object_id,))
        conn.commit()


def archive_object(object_id: int) -> None:
    with sqlite3.connect(get_db_path()) as conn:
        cursor = conn.execute(
            """
            WITH RECURSIVE subtree(object_id) AS (
                SELECT object_id FROM objects
                WHERE object_id = ? AND archived_at IS NULL
                UNION
                SELECT child.object_id
                FROM objects child
                JOIN subtree parent ON child.parent_object_id = parent.object_id
            )
            UPDATE objects SET archived_at = CURRENT_TIMESTAMP
            WHERE object_id IN (SELECT object_id FROM subtree)
                AND archived_at IS NULL
            """,
            (object_id,),
        )
        if cursor.rowcount == 0:
            raise ValueError("object not found")


def save_function(
    function_name: str,
    function_boundries_created: str = "",
    notes: str = "",
    object_id: int | None = None,
) -> int:
    function_name = function_name.strip()
    if not function_name:
        raise ValueError("function_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO functions (
                function_name, function_boundries_created, notes, object_id
            ) VALUES (?, ?, ?, ?)
            """,
            (function_name, function_boundries_created, notes, object_id),
        )
        if object_id is not None:
            conn.execute(
                "INSERT OR IGNORE INTO function_objects (function_id, object_id) VALUES (?, ?)",
                (cursor.lastrowid, object_id),
            )
        conn.commit()
        return cursor.lastrowid


def get_functions_for_account(account_id: int) -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
                     SELECT f.function_id, f.function_name, f.function_boundries_created,
                         f.notes, f.object_id, GROUP_CONCAT(DISTINCT o.object_name) AS object_name
            FROM functions AS f
                 LEFT JOIN function_objects AS fo ON fo.function_id = f.function_id
                 LEFT JOIN objects AS o ON o.object_id = fo.object_id
                 WHERE f.archived_at IS NULL
                     AND (o.account_id = ? OR (f.object_id IS NULL AND fo.object_id IS NULL))
                     GROUP BY f.function_id
            ORDER BY f.function_name COLLATE NOCASE ASC, f.function_id ASC
            """,
            (account_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_functions() -> list[dict]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
                 SELECT f.function_id, f.function_name, f.function_boundries_created,
                     f.notes, f.object_id, o.object_name, o.account_id,
                     a.account_name,
                     GROUP_CONCAT(DISTINCT fo.object_id) AS object_ids,
                     GROUP_CONCAT(DISTINCT o2.object_name) AS object_names
            FROM functions AS f
            LEFT JOIN objects AS o ON o.object_id = f.object_id
            LEFT JOIN accounts AS a ON a.id = o.account_id
                 LEFT JOIN function_objects AS fo ON fo.function_id = f.function_id
                 LEFT JOIN objects AS o2 ON o2.object_id = fo.object_id
                 WHERE f.archived_at IS NULL
                 GROUP BY f.function_id
            ORDER BY f.function_id ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def update_function(
    function_id: int,
    function_name: str,
    function_boundries_created: str,
    notes: str,
    object_id: int | None,
    object_ids: list[int] | None = None,
) -> None:
    function_name = function_name.strip()
    if not function_name:
        raise ValueError("function_name cannot be empty")

    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE functions
            SET function_name = ?, function_boundries_created = ?, notes = ?, object_id = ?
            WHERE function_id = ?
            """,
            (function_name, function_boundries_created, notes, object_id, function_id),
        )
        selected_object_ids = object_ids if object_ids is not None else (
            [object_id] if object_id is not None else []
        )
        conn.execute("DELETE FROM function_objects WHERE function_id = ?", (function_id,))
        conn.executemany(
            "INSERT OR IGNORE INTO function_objects (function_id, object_id) VALUES (?, ?)",
            [(function_id, linked_object_id) for linked_object_id in selected_object_ids],
        )
        conn.commit()


def get_object_ids_for_function(function_id: int) -> list[int]:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT object_id FROM function_objects WHERE function_id = ? ORDER BY object_id",
            (function_id,),
        ).fetchall()
    return [row[0] for row in rows]


def delete_function(function_id: int) -> None:
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM functions WHERE function_id = ?", (function_id,))
        conn.commit()


if __name__ == "__main__":
    db_path = init_db()
    print(f"SQLite database created at: {db_path}")
