import os
import uuid
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2.pool import ThreadedConnectionPool
    from psycopg2.extras import Json, RealDictCursor
except ImportError:  # pragma: no cover - handled at runtime
    psycopg2 = None
    ThreadedConnectionPool = None
    Json = None
    RealDictCursor = None


class StorageRepository(ABC):
    @abstractmethod
    def create_scan(self, status: str = "started", metadata: Optional[Dict[str, Any]] = None) -> str:
        raise NotImplementedError

    @abstractmethod
    def update_scan_status(self, scan_id: str, status: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_reachability(self, scan_id: str, evidence: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_correlation(self, scan_id: str, results: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_raw_output(self, scan_id: str, tool_name: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_semgrep_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def store_routes(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_raw_output(self, scan_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def list_raw_tools(self, scan_id: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def list_scans(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def delete_scan(self, scan_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_connector(self, connector_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def upsert_connector(self, connector_id: str, config: Dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_connector(self, connector_id: str) -> bool:
        raise NotImplementedError


class PostgresRepository(StorageRepository):
    def __init__(self, dsn: Optional[str] = None) -> None:
        if psycopg2 is None:
            raise ImportError("psycopg2 is required for PostgresRepository; install psycopg2-binary")
        self.dsn = dsn or os.getenv("DATABASE_URL")
        if not self.dsn:
            raise ValueError("DATABASE_URL is required for PostgresRepository")
        self.logger = logging.getLogger(__name__)
        self.pool = ThreadedConnectionPool(
            minconn=int(os.getenv("DB_MIN_CONN", "1")),
            maxconn=int(os.getenv("DB_MAX_CONN", "5")),
            dsn=self.dsn,
        )
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS scans (
            id UUID PRIMARY KEY,
            status TEXT NOT NULL,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            package TEXT,
            cve_id JSONB DEFAULT '[]'::jsonb,
            severity TEXT,
            version TEXT,
            fix_version TEXT
        );

        CREATE TABLE IF NOT EXISTS reachability_evidence (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            cve_id TEXT,
            package TEXT,
            import_detected BOOLEAN,
            call_chain_exists BOOLEAN,
            sink_reachable BOOLEAN,
            verdict TEXT,
            file TEXT,
            function TEXT,
            sink TEXT,
            confidence NUMERIC DEFAULT 0.1,
            evidence_type TEXT,
            files JSONB DEFAULT '[]'::jsonb
        );

        CREATE TABLE IF NOT EXISTS correlation_results (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            cve_id TEXT,
            check_id TEXT,
            verdict TEXT,
            risk_score NUMERIC,
            priority TEXT,
            confidence NUMERIC DEFAULT 0.1,
            finding_type TEXT,
            evidence JSONB DEFAULT '{}'::jsonb,
            evidence_type TEXT  -- legacy column kept for old rows
        );

        CREATE TABLE IF NOT EXISTS raw_outputs (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            tool_name TEXT,
            payload JSONB,
            UNIQUE (scan_id, tool_name)
        );

        CREATE TABLE IF NOT EXISTS semgrep_findings (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            check_id TEXT,
            path TEXT,
            start JSONB,
            finish JSONB,
            severity TEXT,
            extra JSONB
        );

        CREATE TABLE IF NOT EXISTS routes_extracted (
            id SERIAL PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            method TEXT,
            path TEXT,
            handler TEXT,
            file TEXT,
            framework TEXT,
            prefix TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_used_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
        """
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
        self._run_migrations()

    def _run_migrations(self) -> None:
        """Apply schema migrations for existing databases."""
        migrations = [
            # Migrate vulnerabilities.cve_id from TEXT to JSONB
            """
            DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='vulnerabilities' AND column_name='cve_id' AND data_type='text'
                ) THEN
                    ALTER TABLE vulnerabilities ALTER COLUMN cve_id TYPE JSONB USING
                        CASE
                            WHEN cve_id IS NULL THEN '[]'::jsonb
                            WHEN cve_id LIKE '{%' THEN to_jsonb(string_to_array(trim(both '{}' from cve_id), ','))
                            ELSE jsonb_build_array(cve_id)
                        END;
                    ALTER TABLE vulnerabilities ALTER COLUMN cve_id SET DEFAULT '[]'::jsonb;
                END IF;
            END $$;
            """,
            # Add evidence_type to reachability_evidence
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='reachability_evidence' AND column_name='evidence_type'
                ) THEN
                    ALTER TABLE reachability_evidence ADD COLUMN evidence_type TEXT;
                END IF;
            END $$;
            """,
            # Add files JSONB to reachability_evidence
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='reachability_evidence' AND column_name='files'
                ) THEN
                    ALTER TABLE reachability_evidence ADD COLUMN files JSONB DEFAULT '[]'::jsonb;
                END IF;
            END $$;
            """,
            # Migrate reachability_evidence.confidence from TEXT to NUMERIC
            """
            DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='reachability_evidence' AND column_name='confidence' AND data_type='text'
                ) THEN
                    ALTER TABLE reachability_evidence ALTER COLUMN confidence TYPE NUMERIC USING
                        CASE WHEN confidence ~ '^[0-9.]+$' THEN confidence::NUMERIC ELSE 0.1 END;
                    ALTER TABLE reachability_evidence ALTER COLUMN confidence SET DEFAULT 0.1;
                END IF;
            END $$;
            """,
            # Add confidence to correlation_results
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='correlation_results' AND column_name='confidence'
                ) THEN
                    ALTER TABLE correlation_results ADD COLUMN confidence NUMERIC DEFAULT 0.1;
                END IF;
            END $$;
            """,
            # Add evidence_type to correlation_results
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='correlation_results' AND column_name='evidence_type'
                ) THEN
                    ALTER TABLE correlation_results ADD COLUMN evidence_type TEXT;
                END IF;
            END $$;
            """,
            # Add finding_type to correlation_results (replaces evidence_type)
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='correlation_results' AND column_name='finding_type'
                ) THEN
                    ALTER TABLE correlation_results ADD COLUMN finding_type TEXT;
                END IF;
            END $$;
            """,
            # Add evidence JSONB to correlation_results
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='correlation_results' AND column_name='evidence'
                ) THEN
                    ALTER TABLE correlation_results ADD COLUMN evidence JSONB DEFAULT '{}'::jsonb;
                END IF;
            END $$;
            """,
            # Add check_id to correlation_results (for semgrep findings)
            """
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='correlation_results' AND column_name='check_id'
                ) THEN
                    ALTER TABLE correlation_results ADD COLUMN check_id TEXT;
                END IF;
            END $$;
            """,
            # Add API key support tables/indexes for existing deployments
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_used_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);",
            "CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);",
            """
            CREATE TABLE IF NOT EXISTS connectors (
                id TEXT PRIMARY KEY,
                config JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
        ]
        with self._conn() as conn:
            with conn.cursor() as cur:
                for migration in migrations:
                    try:
                        cur.execute(migration)
                    except Exception as e:
                        self.logger.warning(f"Migration skipped: {e}")

    def create_scan(self, status: str = "started", metadata: Optional[Dict[str, Any]] = None) -> str:
        scan_id = str(uuid.uuid4())
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "INSERT INTO scans (id, status, metadata) VALUES (%s, %s, %s)",
                    (scan_id, status, Json(metadata or {})),
                )
        return scan_id

    def update_scan_status(self, scan_id: str, status: str) -> None:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("UPDATE scans SET status=%s WHERE id=%s", (status, scan_id))

    def store_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> None:
        if not vulns:
            return
        rows = [
            (
                scan_id,
                vuln.get("package"),
                Json(vuln.get("cve_id") if isinstance(vuln.get("cve_id"), list) else [vuln.get("cve_id")] if vuln.get("cve_id") else []),
                vuln.get("severity"),
                vuln.get("version"),
                vuln.get("fix_version"),
            )
            for vuln in vulns
        ]
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(
                    """
                    INSERT INTO vulnerabilities (scan_id, package, cve_id, severity, version, fix_version)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

    def store_reachability(self, scan_id: str, evidence: List[Dict[str, Any]]) -> None:
        if not evidence:
            return
        rows = []
        for item in evidence:
            files_list = item.get("files") or []
            first_file = files_list[0] if files_list else None
            rows.append(
                (
                    scan_id,
                    item.get("cve_id"),
                    item.get("package"),
                    item.get("import_detected"),
                    item.get("call_chain_exists"),
                    item.get("sink_reachable"),
                    item.get("verdict"),
                    first_file,
                    item.get("function"),
                    item.get("sink"),
                    item.get("confidence", 0.1),
                    item.get("evidence_type"),
                    Json(files_list),
                )
            )
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(
                    """
                    INSERT INTO reachability_evidence
                    (scan_id, cve_id, package, import_detected, call_chain_exists, sink_reachable, verdict, file, function, sink, confidence, evidence_type, files)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

    def store_correlation(self, scan_id: str, results: List[Dict[str, Any]]) -> None:
        if not results:
            return
        rows = [
            (
                scan_id,
                item.get("cve_id"),
                item.get("check_id"),
                item.get("verdict"),
                item.get("risk_score"),
                item.get("priority"),
                item.get("confidence", 0.1),
                item.get("finding_type") or item.get("evidence_type"),  # prefer new field
                Json(item.get("evidence") or {}),
            )
            for item in results
        ]
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(
                    """
                    INSERT INTO correlation_results
                        (scan_id, cve_id, check_id, verdict, risk_score, priority, confidence, finding_type, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

    def store_raw_output(self, scan_id: str, tool_name: str, payload: Dict[str, Any]) -> None:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO raw_outputs (scan_id, tool_name, payload)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (scan_id, tool_name) DO UPDATE SET payload=excluded.payload
                    """,
                    (scan_id, tool_name, Json(payload)),
                )

    def store_semgrep_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            return
        rows = [
            (
                scan_id,
                item.get("check_id"),
                item.get("path"),
                Json(item["start"]) if isinstance(item.get("start"), dict) else item.get("start"),
                Json(item["end"]) if isinstance(item.get("end"), dict) else item.get("end"),
                item.get("severity"),
                Json(item["extra"]) if isinstance(item.get("extra"), dict) else item.get("extra"),
            )
            for item in findings
        ]
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(
                    """
                    INSERT INTO semgrep_findings (scan_id, check_id, path, start, finish, severity, extra)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

    def store_routes(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            return
        rows = [
            (
                scan_id,
                item.get("method"),
                item.get("path"),
                item.get("handler"),
                item.get("file"),
                item.get("framework"),
                item.get("prefix"),
            )
            for item in findings
        ]
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(
                    """
                    INSERT INTO routes_extracted (scan_id, method, path, handler, file, framework, prefix)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, status, metadata, created_at FROM scans WHERE id=%s", (scan_id,))
                scan_row = cur.fetchone()
                if not scan_row:
                    return None

                cur.execute(
                    "SELECT package, cve_id, severity, version, fix_version FROM vulnerabilities WHERE scan_id=%s",
                    (scan_id,),
                )
                vulns = cur.fetchall() or []

                cur.execute(
                    """
                    SELECT cve_id, package, import_detected, call_chain_exists, sink_reachable, verdict, file, function, sink, confidence, evidence_type, files
                    FROM reachability_evidence WHERE scan_id=%s
                    """,
                    (scan_id,),
                )
                reachability = cur.fetchall() or []

                cur.execute(
                    "SELECT cve_id, check_id, verdict, risk_score, priority, confidence, finding_type, evidence FROM correlation_results WHERE scan_id=%s",
                    (scan_id,),
                )
                correlation = cur.fetchall() or []

                cur.execute("SELECT tool_name, payload FROM raw_outputs WHERE scan_id=%s", (scan_id,))
                raw_rows = cur.fetchall() or []
                raw = {row["tool_name"]: row["payload"] for row in raw_rows}

                cur.execute(
                    "SELECT check_id, path, start, finish, severity, extra FROM semgrep_findings WHERE scan_id=%s",
                    (scan_id,),
                )
                semgrep = cur.fetchall() or []

                cur.execute(
                    "SELECT method, path, handler, file, framework, prefix FROM routes_extracted WHERE scan_id=%s",
                    (scan_id,),
                )
                routes = cur.fetchall() or []

                return {
                    "scan_id": scan_row["id"],
                    "status": scan_row["status"],
                    "metadata": scan_row.get("metadata") if isinstance(scan_row, dict) else scan_row[2],
                    "created_at": scan_row.get("created_at") if isinstance(scan_row, dict) else scan_row[3],
                    "vulnerabilities": vulns,
                    "reachability": reachability,
                    "correlation": [self._convert_correlation(row) for row in correlation],
                    "raw": raw,
                    "semgrep_findings": semgrep,
                    "routes": routes,
                }

    def get_raw_output(self, scan_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM raw_outputs WHERE scan_id=%s AND tool_name=%s",
                    (scan_id, tool_name),
                )
                row = cur.fetchone()
                return row["payload"] if row else None

    def list_raw_tools(self, scan_id: str) -> List[str]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT tool_name FROM raw_outputs WHERE scan_id=%s ORDER BY tool_name",
                    (scan_id,),
                )
                return [row["tool_name"] for row in cur.fetchall()]

    def list_scans(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        s.id, s.status, s.metadata, s.created_at,
                        COUNT(DISTINCT v.package)                                                                       AS pkg_count,
                        COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.package END)                           AS critical_pkgs,
                        COUNT(DISTINCT CASE WHEN v.severity = 'HIGH'     THEN v.package END)                           AS high_pkgs,
                        COUNT(DISTINCT CASE WHEN v.severity = 'MEDIUM'   THEN v.package END)                           AS medium_pkgs,
                        COUNT(DISTINCT CASE WHEN v.severity = 'LOW'      THEN v.package END)                           AS low_pkgs,
                        COUNT(DISTINCT CASE WHEN c.evidence->>'reachability_class' = 'DYNAMICALLY_REACHABLE' THEN v.package END)    AS confirmed_pkgs,
                        COUNT(DISTINCT CASE WHEN c.evidence->>'reachability_class' = 'STATICALLY_REACHABLE'  THEN v.package END)    AS likely_pkgs
                    FROM scans s
                    LEFT JOIN correlation_results c  ON c.scan_id = s.id
                    LEFT JOIN vulnerabilities v      ON v.scan_id = s.id
                                                    AND v.cve_id @> to_jsonb(c.cve_id)
                    GROUP BY s.id, s.status, s.metadata, s.created_at
                    ORDER BY s.created_at DESC
                """)
                rows = cur.fetchall() or []
                return [
                    {
                        "scan_id":      row["id"],
                        "status":       row["status"],
                        "metadata":     row.get("metadata") if isinstance(row, dict) else row[2],
                        "created_at":   row.get("created_at") if isinstance(row, dict) else row[3],
                        "pkg_count":      int(row["pkg_count"])      if row.get("pkg_count")      else 0,
                        "confirmed_pkgs": int(row["confirmed_pkgs"]) if row.get("confirmed_pkgs") else 0,
                        "likely_pkgs":    int(row["likely_pkgs"])    if row.get("likely_pkgs")    else 0,
                        "sev_breakdown": {
                            "CRITICAL": int(row["critical_pkgs"]) if row.get("critical_pkgs") else 0,
                            "HIGH":     int(row["high_pkgs"])     if row.get("high_pkgs")     else 0,
                            "MEDIUM":   int(row["medium_pkgs"])   if row.get("medium_pkgs")   else 0,
                            "LOW":      int(row["low_pkgs"])      if row.get("low_pkgs")      else 0,
                        },
                    }
                    for row in rows
                ]

    def delete_scan(self, scan_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
                return cur.rowcount > 0

    # ── User management ──────────────────────────────────────────────

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE username=%s",
                    (username,),
                )
                return cur.fetchone()

    def create_user(self, user_id: str, username: str, password_hash: str, role: str = "analyst") -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (id, username, password_hash, role) VALUES (%s, %s, %s, %s) ON CONFLICT (username) DO NOTHING",
                    (user_id, username, password_hash, role),
                )

    def create_api_key(
        self,
        key_id: str,
        user_id: str,
        name: str,
        key_prefix: str,
        key_hash: str,
        expires_at: Optional[Any] = None,
    ) -> Dict[str, Any]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, user_id, name, key_prefix, created_at, last_used_at, expires_at, revoked_at
                    """,
                    (key_id, user_id, name, key_prefix, key_hash, expires_at),
                )
                return cur.fetchone()

    def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, user_id, name, key_prefix, created_at, last_used_at, expires_at, revoked_at
                    FROM api_keys
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    """,
                    (user_id,),
                )
                return cur.fetchall() or []

    def get_user_for_api_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        ak.id AS key_id,
                        u.id AS user_id,
                        u.username,
                        u.role
                    FROM api_keys ak
                    JOIN users u ON u.id = ak.user_id
                    WHERE ak.key_hash = %s
                      AND ak.revoked_at IS NULL
                      AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
                    LIMIT 1
                    """,
                    (key_hash,),
                )
                return cur.fetchone()

    def get_api_key_candidates_by_prefix(self, key_prefix: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        ak.id AS key_id,
                        ak.key_hash,
                        u.id AS user_id,
                        u.username,
                        u.role
                    FROM api_keys ak
                    JOIN users u ON u.id = ak.user_id
                    WHERE ak.key_prefix = %s
                      AND ak.revoked_at IS NULL
                      AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
                    """,
                    (key_prefix,),
                )
                return list(cur.fetchall() or [])

    def touch_api_key_last_used(self, key_id: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = %s",
                    (key_id,),
                )

    def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE api_keys
                    SET revoked_at = NOW()
                    WHERE id = %s AND user_id = %s AND revoked_at IS NULL
                    """,
                    (key_id, user_id),
                )
                return cur.rowcount > 0

    def delete_api_key(self, key_id: str, user_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM api_keys WHERE id = %s AND user_id = %s",
                    (key_id, user_id),
                )
                return cur.rowcount > 0

    # ── Connectors ────────────────────────────────────────────────────

    def get_connector(self, connector_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT config FROM connectors WHERE id = %s", (connector_id,))
                row = cur.fetchone()
        if not row:
            return None
        cfg = row["config"]
        return dict(cfg) if cfg else {}

    def upsert_connector(self, connector_id: str, config: Dict[str, Any]) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO connectors (id, config, updated_at)
                       VALUES (%s, %s, NOW())
                       ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()""",
                    (connector_id, Json(config)),
                )

    def delete_connector(self, connector_id: str) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM connectors WHERE id = %s", (connector_id,))
                return cur.rowcount > 0

    def _convert_correlation(self, row: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = row.get("risk_score")
        if risk_score is not None:
            try:
                risk_score = float(risk_score)
            except (TypeError, ValueError):
                pass
        confidence = row.get("confidence")
        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                pass
        finding_type = row.get("finding_type") or row.get("evidence_type")
        evidence = row.get("evidence") or {}
        result: Dict[str, Any] = {
            "cve_id":            row.get("cve_id"),
            "check_id":          row.get("check_id"),
            "verdict":           row.get("verdict"),
            "risk_score":        risk_score,
            "priority":          row.get("priority"),
            "confidence":        confidence,
            "finding_type":      finding_type,
            "evidence":          evidence,
        }
        # Promote classification fields stored in evidence blob to top-level
        # so API consumers and the dashboard don't have to dig into evidence.
        if evidence.get("reachability_class"):
            result["reachability_class"] = evidence["reachability_class"]
        if evidence.get("static_subtype"):
            result["static_subtype"] = evidence["static_subtype"]
        return result
