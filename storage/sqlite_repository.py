"""
SQLiteRepository — zero-infrastructure StorageRepository implementation.

Uses Python stdlib sqlite3 so no extra dependencies are required.
Intended for local CLI use and single-user deployments.
Postgres is still recommended for multi-user server deployments.
"""

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from storage.repository import StorageRepository


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _j(value: Any) -> str:
    """Serialize to JSON string for storage."""
    return json.dumps(value)


def _p(value: Optional[str]) -> Any:
    """Parse a JSON string column; return {} / [] / None gracefully."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


class SQLiteRepository(StorageRepository):
    """StorageRepository backed by a local SQLite database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            metadata TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            package TEXT,
            cve_id TEXT DEFAULT '[]',
            severity TEXT,
            version TEXT,
            fix_version TEXT
        );

        CREATE TABLE IF NOT EXISTS reachability_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            cve_id TEXT,
            package TEXT,
            import_detected INTEGER,
            call_chain_exists INTEGER,
            sink_reachable INTEGER,
            verdict TEXT,
            file TEXT,
            function TEXT,
            sink TEXT,
            confidence REAL DEFAULT 0.1,
            evidence_type TEXT,
            files TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS correlation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            cve_id TEXT,
            check_id TEXT,
            verdict TEXT,
            risk_score REAL,
            priority TEXT,
            confidence REAL DEFAULT 0.1,
            finding_type TEXT,
            evidence TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS raw_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            tool_name TEXT,
            payload TEXT,
            UNIQUE (scan_id, tool_name)
        );

        CREATE TABLE IF NOT EXISTS semgrep_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            check_id TEXT,
            path TEXT,
            start TEXT,
            finish TEXT,
            severity TEXT,
            extra TEXT
        );

        CREATE TABLE IF NOT EXISTS routes_extracted (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
            method TEXT,
            path TEXT,
            handler TEXT,
            file TEXT,
            framework TEXT,
            prefix TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            last_used_at TEXT,
            expires_at TEXT,
            revoked_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);

        CREATE TABLE IF NOT EXISTS connectors (
            id TEXT PRIMARY KEY,
            config TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        """
        with self._conn() as conn:
            conn.executescript(ddl)

    # ── Scan lifecycle ────────────────────────────────────────────────

    def create_scan(self, status: str = "started", metadata: Optional[Dict[str, Any]] = None) -> str:
        scan_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scans (id, status, metadata) VALUES (?, ?, ?)",
                (scan_id, status, _j(metadata or {})),
            )
        return scan_id

    def update_scan_status(self, scan_id: str, status: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))

    # ── Storage methods ───────────────────────────────────────────────

    def store_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> None:
        if not vulns:
            return
        rows = [
            (
                scan_id,
                v.get("package"),
                _j(v.get("cve_id") if isinstance(v.get("cve_id"), list) else [v.get("cve_id")] if v.get("cve_id") else []),
                v.get("severity"),
                v.get("version"),
                v.get("fix_version"),
            )
            for v in vulns
        ]
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO vulnerabilities (scan_id, package, cve_id, severity, version, fix_version) VALUES (?,?,?,?,?,?)",
                rows,
            )

    def store_reachability(self, scan_id: str, evidence: List[Dict[str, Any]]) -> None:
        if not evidence:
            return
        rows = []
        for item in evidence:
            files_list = item.get("files") or []
            rows.append((
                scan_id,
                item.get("cve_id"),
                item.get("package"),
                int(bool(item.get("import_detected"))),
                int(bool(item.get("call_chain_exists"))),
                int(bool(item.get("sink_reachable"))),
                item.get("verdict"),
                files_list[0] if files_list else None,
                item.get("function"),
                item.get("sink"),
                item.get("confidence", 0.1),
                item.get("evidence_type"),
                _j(files_list),
            ))
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO reachability_evidence
                   (scan_id,cve_id,package,import_detected,call_chain_exists,sink_reachable,
                    verdict,file,function,sink,confidence,evidence_type,files)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                item.get("finding_type") or item.get("evidence_type"),
                _j(item.get("evidence") or {}),
            )
            for item in results
        ]
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO correlation_results
                   (scan_id,cve_id,check_id,verdict,risk_score,priority,confidence,finding_type,evidence)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def store_raw_output(self, scan_id: str, tool_name: str, payload: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO raw_outputs (scan_id, tool_name, payload) VALUES (?,?,?)
                   ON CONFLICT(scan_id, tool_name) DO UPDATE SET payload=excluded.payload""",
                (scan_id, tool_name, _j(payload)),
            )

    def store_semgrep_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            return
        rows = [
            (scan_id, f.get("check_id"), f.get("path"), _j(f.get("start")), _j(f.get("end")), f.get("severity"), _j(f.get("extra")))
            for f in findings
        ]
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO semgrep_findings (scan_id,check_id,path,start,finish,severity,extra) VALUES (?,?,?,?,?,?,?)",
                rows,
            )

    def store_routes(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            return
        rows = [
            (scan_id, f.get("method"), f.get("path"), f.get("handler"), f.get("file"), f.get("framework"), f.get("prefix"))
            for f in findings
        ]
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO routes_extracted (scan_id,method,path,handler,file,framework,prefix) VALUES (?,?,?,?,?,?,?)",
                rows,
            )

    # ── Retrieval ─────────────────────────────────────────────────────

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id,status,metadata,created_at FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            if not row:
                return None

            vulns = conn.execute(
                "SELECT package,cve_id,severity,version,fix_version FROM vulnerabilities WHERE scan_id=?",
                (scan_id,),
            ).fetchall()

            reach = conn.execute(
                """SELECT cve_id,package,import_detected,call_chain_exists,sink_reachable,
                          verdict,file,function,sink,confidence,evidence_type,files
                   FROM reachability_evidence WHERE scan_id=?""",
                (scan_id,),
            ).fetchall()

            corr = conn.execute(
                "SELECT cve_id,check_id,verdict,risk_score,priority,confidence,finding_type,evidence FROM correlation_results WHERE scan_id=?",
                (scan_id,),
            ).fetchall()

            raw_rows = conn.execute(
                "SELECT tool_name,payload FROM raw_outputs WHERE scan_id=?", (scan_id,)
            ).fetchall()

            semgrep = conn.execute(
                "SELECT check_id,path,start,finish,severity,extra FROM semgrep_findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()

            routes = conn.execute(
                "SELECT method,path,handler,file,framework,prefix FROM routes_extracted WHERE scan_id=?",
                (scan_id,),
            ).fetchall()

        def _vuln(r):
            return {"package": r["package"], "cve_id": _p(r["cve_id"]) or [], "severity": r["severity"], "version": r["version"], "fix_version": r["fix_version"]}

        def _reach(r):
            return {
                "cve_id": r["cve_id"], "package": r["package"],
                "import_detected": bool(r["import_detected"]), "call_chain_exists": bool(r["call_chain_exists"]),
                "sink_reachable": bool(r["sink_reachable"]), "verdict": r["verdict"],
                "file": r["file"], "function": r["function"], "sink": r["sink"],
                "confidence": r["confidence"], "evidence_type": r["evidence_type"],
                "files": _p(r["files"]) or [],
            }

        def _semgrep(r):
            return {"check_id": r["check_id"], "path": r["path"], "start": _p(r["start"]), "finish": _p(r["finish"]), "severity": r["severity"], "extra": _p(r["extra"])}

        def _route(r):
            return {"method": r["method"], "path": r["path"], "handler": r["handler"], "file": r["file"], "framework": r["framework"], "prefix": r["prefix"]}

        return {
            "scan_id": row["id"],
            "status": row["status"],
            "metadata": _p(row["metadata"]) or {},
            "created_at": row["created_at"],
            "vulnerabilities": [_vuln(r) for r in vulns],
            "reachability": [_reach(r) for r in reach],
            "correlation": [self._convert_correlation(dict(r)) for r in corr],
            "raw": {r["tool_name"]: _p(r["payload"]) for r in raw_rows},
            "semgrep_findings": [_semgrep(r) for r in semgrep],
            "routes": [_route(r) for r in routes],
        }

    def get_raw_output(self, scan_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload FROM raw_outputs WHERE scan_id=? AND tool_name=?",
                (scan_id, tool_name),
            ).fetchone()
        return _p(row["payload"]) if row else None

    def list_raw_tools(self, scan_id: str) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT tool_name FROM raw_outputs WHERE scan_id=? ORDER BY tool_name",
                (scan_id,),
            ).fetchall()
        return [r["tool_name"] for r in rows]

    def list_scans(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            scans = conn.execute(
                "SELECT id,status,metadata,created_at FROM scans ORDER BY created_at DESC"
            ).fetchall()
            results = []
            for s in scans:
                sid = s["id"]
                pkg_count = conn.execute(
                    "SELECT COUNT(DISTINCT package) FROM vulnerabilities WHERE scan_id=?", (sid,)
                ).fetchone()[0] or 0

                sev_rows = conn.execute(
                    "SELECT severity, COUNT(DISTINCT package) AS cnt FROM vulnerabilities WHERE scan_id=? GROUP BY severity",
                    (sid,),
                ).fetchall()
                sev = {r["severity"]: r["cnt"] for r in sev_rows}

                confirmed = conn.execute(
                    """SELECT COUNT(DISTINCT cr.cve_id) FROM correlation_results cr
                       WHERE cr.scan_id=? AND json_extract(cr.evidence,'$.reachability_class')='DYNAMICALLY_REACHABLE'""",
                    (sid,),
                ).fetchone()[0] or 0

                likely = conn.execute(
                    """SELECT COUNT(DISTINCT cr.cve_id) FROM correlation_results cr
                       WHERE cr.scan_id=? AND json_extract(cr.evidence,'$.reachability_class')='STATICALLY_REACHABLE'""",
                    (sid,),
                ).fetchone()[0] or 0

                results.append({
                    "scan_id": sid,
                    "status": s["status"],
                    "metadata": _p(s["metadata"]) or {},
                    "created_at": s["created_at"],
                    "pkg_count": int(pkg_count),
                    "confirmed_pkgs": int(confirmed),
                    "likely_pkgs": int(likely),
                    "sev_breakdown": {
                        "CRITICAL": int(sev.get("CRITICAL", 0)),
                        "HIGH": int(sev.get("HIGH", 0)),
                        "MEDIUM": int(sev.get("MEDIUM", 0)),
                        "LOW": int(sev.get("LOW", 0)),
                    },
                })
        return results

    def delete_scan(self, scan_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return cur.rowcount > 0

    # ── User management ───────────────────────────────────────────────

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id,username,password_hash,role FROM users WHERE username=?", (username,)
            ).fetchone()
        return dict(row) if row else None

    def create_user(self, user_id: str, username: str, password_hash: str, role: str = "analyst") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (id,username,password_hash,role) VALUES (?,?,?,?)",
                (user_id, username, password_hash, role),
            )

    def create_api_key(self, key_id: str, user_id: str, name: str, key_prefix: str, key_hash: str, expires_at: Optional[Any] = None) -> Dict[str, Any]:
        now = _now_iso()
        expires_str = expires_at.isoformat() if hasattr(expires_at, "isoformat") else (str(expires_at) if expires_at else None)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO api_keys (id,user_id,name,key_prefix,key_hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                (key_id, user_id, name, key_prefix, key_hash, now, expires_str),
            )
        return {"id": key_id, "user_id": user_id, "name": name, "key_prefix": key_prefix, "created_at": now, "last_used_at": None, "expires_at": expires_str, "revoked_at": None}

    def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id,user_id,name,key_prefix,created_at,last_used_at,expires_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_user_for_api_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT ak.id AS key_id, u.id AS user_id, u.username, u.role
                   FROM api_keys ak JOIN users u ON u.id=ak.user_id
                   WHERE ak.key_hash=? AND ak.revoked_at IS NULL
                     AND (ak.expires_at IS NULL OR ak.expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                   LIMIT 1""",
                (key_hash,),
            ).fetchone()
        return dict(row) if row else None

    def get_api_key_candidates_by_prefix(self, key_prefix: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT ak.id AS key_id, ak.key_hash, u.id AS user_id, u.username, u.role
                   FROM api_keys ak JOIN users u ON u.id=ak.user_id
                   WHERE ak.key_prefix=? AND ak.revoked_at IS NULL
                     AND (ak.expires_at IS NULL OR ak.expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now'))""",
                (key_prefix,),
            ).fetchall()
        return [dict(r) for r in rows]

    def touch_api_key_last_used(self, key_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at=? WHERE id=?",
                (_now_iso(), key_id),
            )

    def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
                (_now_iso(), key_id, user_id),
            )
        return cur.rowcount > 0

    def delete_api_key(self, key_id: str, user_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM api_keys WHERE id=? AND user_id=?",
                (key_id, user_id),
            )
        return cur.rowcount > 0

    # ── Connectors ────────────────────────────────────────────────────

    def get_connector(self, connector_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT config FROM connectors WHERE id=?", (connector_id,)
            ).fetchone()
        if not row:
            return None
        return _p(row["config"]) or {}

    def upsert_connector(self, connector_id: str, config: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO connectors (id, config, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at""",
                (connector_id, _j(config), _now_iso()),
            )

    def delete_connector(self, connector_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM connectors WHERE id=?", (connector_id,))
        return cur.rowcount > 0

    # ── Shared helpers ────────────────────────────────────────────────

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
        evidence = _p(row.get("evidence")) if isinstance(row.get("evidence"), str) else (row.get("evidence") or {})
        result: Dict[str, Any] = {
            "cve_id": row.get("cve_id"),
            "check_id": row.get("check_id"),
            "verdict": row.get("verdict"),
            "risk_score": risk_score,
            "priority": row.get("priority"),
            "confidence": confidence,
            "finding_type": finding_type,
            "evidence": evidence,
        }
        if isinstance(evidence, dict):
            if evidence.get("reachability_class"):
                result["reachability_class"] = evidence["reachability_class"]
            if evidence.get("static_subtype"):
                result["static_subtype"] = evidence["static_subtype"]
        return result
