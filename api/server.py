from dotenv import load_dotenv
from pathlib import Path
import os
import uuid
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import asyncio

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from agents.runner import AgentRunner
from api.auth import (
    UserPrincipal,
    create_token,
    hash_api_key,
    hash_password,
    require_user,
    set_api_key_validator,
    verify_api_key,
    verify_password,
)
from vulnreach.scan_response import augment_scan_response
from core.orchestrator import Orchestrator
from config.schema import load_config, default_config
from correlation.service import CorrelationService
from correlation.rbom import rbom_from_scan, to_cyclonedx
from storage import get_repository

# Load .env.local first (secrets), then .env as fallback
load_dotenv(dotenv_path=Path(".env.local"), override=True)
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_audit = logging.getLogger("vulnreach.audit")

# ── Rate limiter ──────────────────────────────────────────────────
_limiter = Limiter(key_func=get_remote_address)

# ── Body size guard ───────────────────────────────────────────────
_MAX_BODY_BYTES = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(1 * 1024 * 1024)))  # default 1 MB

class _MaxBodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > _MAX_BODY_BYTES:
            return Response(
                content=f"Request body exceeds {_MAX_BODY_BYTES} bytes",
                status_code=413,
            )
        return await call_next(request)

app = FastAPI(title="VulnReach v2")
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — configure allowed origins via CORS_ORIGINS env var (comma-separated).
# Defaults to no cross-origin access (same-origin only) when unset.
# Example: CORS_ORIGINS=https://app.example.com,https://ci.example.com
_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if not _cors_origins:
    import logging as _logging
    _logging.getLogger(__name__).info(
        "CORS_ORIGINS not set — cross-origin requests are blocked. "
        "Set CORS_ORIGINS env var to allow specific origins."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=bool(_cors_origins),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(_MaxBodySizeMiddleware)

storage = get_repository()
runner = AgentRunner(storage)
correlation_service = CorrelationService()
orchestrator = Orchestrator(storage, runner, correlation_service)
AVAILABLE_TOOLS: List[str] = [
    "git",
    "trivy",
    "tainter",
    "python_reachability",
    "java_reachability",
    "multi_language_reachability",
    "dynamic_reachability",
    "intelligent_dast",
    "semgrep",
    "route_extractor",
    "metadata",
    "pytest_coverage",
    "openapi_generator",
]

# Registry of in-progress scan tasks — keyed by scan_id
_active_scans: Dict[str, "asyncio.Task[None]"] = {}


# ── Seed admin user on startup ───────────────────────────────────

def _log_runtime_docker_configuration() -> None:
    allow_dynamic = (os.getenv("VULNREACH_ALLOW_DOCKER_DAEMON", "") or "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    docker_host = (os.getenv("DOCKER_HOST", "") or "").strip()

    if allow_dynamic and not docker_host:
        logger.warning(
            "Dynamic Docker scans are enabled but DOCKER_HOST is not set. "
            "Docker CLI will fall back to /var/run/docker.sock and compose-mode runtime scans will fail in the container."
        )
        return

    if allow_dynamic:
        logger.info("Dynamic Docker scans enabled via DOCKER_HOST=%s", docker_host)
        return

    if docker_host:
        logger.info("DOCKER_HOST is set (%s) but dynamic Docker scans are not enabled", docker_host)

def _seed_admin() -> None:
    username = os.getenv("SEED_ADMIN_USERNAME")
    password = os.getenv("SEED_ADMIN_PASSWORD")
    if not username or not password:
        logger.info("SEED_ADMIN_USERNAME/PASSWORD not set — skipping admin seed")
        return
    existing = storage.get_user_by_username(username)
    if existing:
        return
    storage.create_user(
        user_id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role="admin",
    )
    logger.info("Seeded admin user '%s'", username)


@app.on_event("startup")
async def on_startup() -> None:
    _log_runtime_docker_configuration()
    _seed_admin()


def _resolve_api_key_principal(raw_key: str) -> UserPrincipal | None:
    # Extract prefix (e.g., "vrk_ab12cd34") for prefix-based lookup.
    # This is needed because salted hashes are non-deterministic.
    prefix = raw_key.split(".")[0] if "." in raw_key else raw_key
    candidates = storage.get_api_key_candidates_by_prefix(prefix)
    for row in candidates:
        if verify_api_key(raw_key, row.get("key_hash", "")):
            key_id = str(row.get("key_id") or "")
            if key_id:
                storage.touch_api_key_last_used(key_id)
            return UserPrincipal(
                id=str(row["user_id"]),
                username=row["username"],
                role=row["role"],
            )
    return None


set_api_key_validator(_resolve_api_key_principal)


# ── Auth endpoints ───────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ApiKeyCreateRequest(BaseModel):
    name: str = "default"
    expires_in_days: int | None = 30


@app.post("/login")
@_limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    user = storage.get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    principal = UserPrincipal(id=str(user["id"]), username=user["username"], role=user["role"])
    return {"access_token": create_token(principal), "token_type": "bearer"}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _serialize_api_key_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row.get("id")),
        "user_id": str(row.get("user_id")),
        "name": row.get("name"),
        "key_prefix": row.get("key_prefix"),
        "created_at": _iso(row.get("created_at")),
        "last_used_at": _iso(row.get("last_used_at")),
        "expires_at": _iso(row.get("expires_at")),
        "revoked_at": _iso(row.get("revoked_at")),
    }


@app.get("/api-keys")
async def list_api_keys(principal: UserPrincipal = Depends(require_user)):
    keys = storage.list_api_keys(principal.id)
    return {"api_keys": [_serialize_api_key_row(k) for k in keys]}


@app.post("/api-keys")
async def create_api_key(body: ApiKeyCreateRequest, principal: UserPrincipal = Depends(require_user)):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if len(name) > 120:
        raise HTTPException(status_code=400, detail="name must be <= 120 characters")
    if body.expires_in_days is not None and (body.expires_in_days < 1 or body.expires_in_days > 3650):
        raise HTTPException(status_code=400, detail="expires_in_days must be between 1 and 3650")

    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    key_prefix = f"vrk_{secrets.token_hex(4)}"
    api_key = f"{key_prefix}.{secrets.token_urlsafe(32)}"
    key_hash = hash_api_key(api_key)
    key_id = str(uuid.uuid4())
    row = storage.create_api_key(
        key_id=key_id,
        user_id=principal.id,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        expires_at=expires_at,
    )

    return {
        "api_key": api_key,
        "warning": "Store this key now. It will not be shown again.",
        "key": _serialize_api_key_row(row),
    }


@app.post("/api-keys/{key_id}/revoke")
async def revoke_api_key(key_id: str, principal: UserPrincipal = Depends(require_user)):
    revoked = storage.revoke_api_key(key_id, principal.id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found or already revoked")
    return {"id": key_id, "revoked": True}


@app.delete("/api-keys/{key_id}")
async def delete_api_key(key_id: str, principal: UserPrincipal = Depends(require_user)):
    deleted = storage.delete_api_key(key_id, principal.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"id": key_id, "deleted": True}


# ── Helpers ──────────────────────────────────────────────────────

def _fetch_scan_owned(scan_id: str, principal: UserPrincipal) -> dict:
    """Fetch a scan and enforce ownership.

    Admins can access any scan. Analysts can only access scans they created.
    Always raises 404 (never 403) so scan IDs cannot be enumerated by probing
    for ownership-mismatch errors.
    """
    try:
        scan = storage.get_scan(scan_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if principal.role != "admin":
        owner_id = (scan.get("metadata") or {}).get("created_by", {}).get("id")
        if owner_id != principal.id:
            # Return 404, not 403 — avoids confirming the scan exists
            raise HTTPException(status_code=404, detail="Scan not found")
    _audit.info("scan_accessed scan_id=%s user=%s", scan_id, principal.username)
    return scan


# ── Protected endpoints ──────────────────────────────────────────

@app.post("/scan")
async def start_scan(
    payload: Dict[str, Any],
    _principal: UserPrincipal = Depends(require_user),
):
    repo_path = payload.get("repo_path")
    repo_url = payload.get("repo_url")
    config_path = payload.get("config_path") or ""
    logger.info("[scan] request: repo_path=%r repo_url=%r config_path=%r", repo_path, repo_url, config_path)
    if not repo_path and not repo_url:
        raise HTTPException(status_code=400, detail="repo_path or repo_url is required")
    # config_path is optional when repo_url is provided.
    # Without it, the cloned repository must provide vulnreach.yaml at repo root.
    if not config_path and not repo_url:
        raise HTTPException(status_code=400, detail="config_path is required for local repo scans")

    if config_path:
        try:
            config = load_config(config_path)
        except (FileNotFoundError, ValueError) as exc:
            logger.warning("[scan] config load failed: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        config = default_config()

    requested_tools = payload.get("tools")
    tools = list(requested_tools if requested_tools else (config.scan.tools or []))

    # Auto-inject dynamic_reachability if runtime is enabled and not already present
    if config.scan.runtime.enabled and "dynamic_reachability" not in tools:
        tools.append("dynamic_reachability")

    if repo_url and "git" not in tools:
        tools.insert(0, "git")

    # Validate all tools are known
    unknown = set(tools) - set(AVAILABLE_TOOLS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown tools: {sorted(unknown)}")

    # Keep runtime tool execution aligned with the selected tools persisted in metadata.
    config.scan.tools = tools

    scan_id = storage.create_scan(metadata={
        "repo_path": repo_path,
        "repo_url": repo_url,
        "tools": tools,
        "created_by": {"id": _principal.id, "username": _principal.username},
    })
    _audit.info("scan_created scan_id=%s user=%s repo_url=%r repo_path=%r tools=%s",
                scan_id, _principal.username, repo_url, repo_path, tools)

    task = asyncio.create_task(
        orchestrator.execute_scan(scan_id, repo_path or "", config_path, config, repo_url)
    )
    _active_scans[scan_id] = task
    task.add_done_callback(lambda _: _active_scans.pop(scan_id, None))

    return {"scan_id": scan_id, "status": "started", "tools": tools, "repo_path": repo_path, "repo_url": repo_url}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    scan = _fetch_scan_owned(scan_id, principal)
    return {"scan_id": scan_id, **augment_scan_response(scan)}


@app.get("/scan/{scan_id}/rbom")
async def get_rbom(scan_id: str, format: str = "json",
                   principal: UserPrincipal = Depends(require_user)):
    """Reachability Bill of Materials — the scan's components keyed by package,
    each with its reachability verdict and layered evidence.

    ``format=json`` (default) returns the native RBOM; ``format=cyclonedx``
    returns CycloneDX 1.5 with reachability encoded as VEX analysis state.
    """
    scan = _fetch_scan_owned(scan_id, principal)
    scan.setdefault("scan_id", scan_id)
    rbom = rbom_from_scan(scan)
    if format.lower() in ("cyclonedx", "cdx"):
        return to_cyclonedx(rbom)
    return rbom


@app.post("/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    scan = _fetch_scan_owned(scan_id, principal)
    if scan.get("status") not in ("started", "running"):
        raise HTTPException(status_code=409, detail=f"Scan is not running (status: {scan.get('status')})")
    task = _active_scans.get(scan_id)
    if task and not task.done():
        task.cancel()
    storage.update_scan_status(scan_id, "cancelled")
    _audit.info("scan_cancelled scan_id=%s user=%s", scan_id, principal.username)
    return {"scan_id": scan_id, "status": "cancelled"}


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    _fetch_scan_owned(scan_id, principal)
    task = _active_scans.pop(scan_id, None)
    if task and not task.done():
        task.cancel()
    deleted = storage.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    _audit.info("scan_deleted scan_id=%s user=%s", scan_id, principal.username)
    return {"scan_id": scan_id, "deleted": True}


@app.get("/scan/{scan_id}/raw")
async def list_raw_tools(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    """List all tool names that have raw output stored for this scan."""
    _fetch_scan_owned(scan_id, principal)  # ownership + existence check
    tools = storage.list_raw_tools(scan_id)
    return {"scan_id": scan_id, "tools": tools}


@app.get("/scan/{scan_id}/raw/{tool_name}")
async def get_raw_output(scan_id: str, tool_name: str, principal: UserPrincipal = Depends(require_user)):
    """Get the raw output payload for a specific tool in a scan."""
    _fetch_scan_owned(scan_id, principal)  # ownership + existence check
    payload = storage.get_raw_output(scan_id, tool_name)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"No raw output for tool '{tool_name}'")
    return {"scan_id": scan_id, "tool_name": tool_name, "output": payload}


@app.get("/scans")
async def list_scans(principal: UserPrincipal = Depends(require_user)):
    all_scans = storage.list_scans()
    if principal.role == "admin":
        return {"scans": all_scans}
    # Analysts see only their own scans
    return {"scans": [
        s for s in all_scans
        if (s.get("metadata") or {}).get("created_by", {}).get("id") == principal.id
    ]}


@app.get("/scan/{scan_id}/fix-plan")
async def get_fix_plan(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    """Return a prioritised list of package upgrades that remove reachable CVEs."""
    scan = _fetch_scan_owned(scan_id, principal)
    from api.fix_plan import build_fix_plan
    plan = build_fix_plan(scan)
    fixable = sum(len(p["reachable_cves_removed"]) for p in plan)
    return {
        "scan_id": scan_id,
        "fix_plan": plan,
        "summary": {
            "reachable_cves_fixable": fixable,
            "packages_to_upgrade": len(plan),
        },
    }


@app.get("/scan/{scan_id}/graph/{cve_id}")
async def get_call_graph(scan_id: str, cve_id: str, principal: UserPrincipal = Depends(require_user)):
    """Return the Mermaid call-chain graph for a specific CVE in a scan."""
    scan = _fetch_scan_owned(scan_id, principal)

    # Step 1: resolve which package this CVE belongs to via reachability evidence
    pkg_name = None
    for ev in scan.get("reachability") or []:
        if ev.get("cve_id") == cve_id:
            pkg_name = ev.get("package")
            break
    if not pkg_name:
        for vuln in scan.get("vulnerabilities") or []:
            if vuln.get("cve_id") == cve_id:
                pkg_name = vuln.get("package")
                break
    if not pkg_name:
        raise HTTPException(status_code=404, detail=f"No finding for CVE '{cve_id}' in scan '{scan_id}'")

    # Step 2: search raw analyses for the package's call_chain_graph
    # Python raw: {"vulnerabilities": [{"package_name": ..., "call_chain_graph": ...}]}
    # Java/multi raw: {"analyses": [{"package_name": ..., "call_chain_graph": ...}]}
    raw = scan.get("raw") or {}
    for tool_name in ("python_reachability", "java_reachability", "multi_language_reachability"):
        payload = raw.get(tool_name) or {}
        analyses = payload.get("vulnerabilities") or payload.get("analyses") or []
        for analysis in analyses:
            if analysis.get("package_name") == pkg_name:
                graph = analysis.get("call_chain_graph")
                if graph:
                    return {
                        "scan_id": scan_id,
                        "cve_id": cve_id,
                        "package": pkg_name,
                        "call_chain_graph": graph,
                    }
    raise HTTPException(status_code=404, detail=f"No call graph found for CVE '{cve_id}'")


class ExplainRequest(BaseModel):
    provider: str = "none"
    model: str | None = None


@app.post("/scan/{scan_id}/explain/{cve_id}")
async def explain_finding(
    scan_id: str,
    cve_id: str,
    body: ExplainRequest,
    principal: UserPrincipal = Depends(require_user),
):
    """Return a human-readable explanation for a CVE finding.

    provider=none (default) returns an offline structured summary.
    provider=anthropic calls the configured Anthropic LLM.
    provider=ollama calls the Ollama instance at VULNREACH_OLLAMA_URL (server-side config only).
    """
    scan = _fetch_scan_owned(scan_id, principal)
    ollama_url = os.getenv("VULNREACH_OLLAMA_URL", "http://host.docker.internal:11434")
    from api.explain import build_explanation
    explanation = build_explanation(scan, cve_id, provider=body.provider, model=body.model, ollama_url=ollama_url)
    return {"scan_id": scan_id, "cve_id": cve_id, "explanation": explanation}


class NextStepsRequest(BaseModel):
    bypass_cache: bool = False
    model: str | None = None


_next_steps_service = None


def _get_next_steps_service():
    """Lazy singleton so missing ANTHROPIC_API_KEY does not crash startup."""
    global _next_steps_service
    if _next_steps_service is None:
        from api.next_steps import NextStepsService
        _next_steps_service = NextStepsService(storage)
    return _next_steps_service


@app.post("/findings/{finding_id}/next-steps")
async def finding_next_steps(
    finding_id: str,
    body: NextStepsRequest | None = None,
    principal: UserPrincipal = Depends(require_user),
):
    """On-demand analyst augmentation for a deterministic finding.

    ``finding_id`` is ``<scan_id>:<cve_id>`` (optionally
    ``<scan_id>:<cve_id>:<package>``). The verdict is owned by the
    correlation engine — this endpoint never mutates it.

    LLM failures degrade gracefully: the response still returns the
    EvidenceGraph + cache metadata with ``status="degraded"``.
    """
    from api.next_steps import parse_finding_id

    try:
        scan_id, _cve_id, _pkg = parse_finding_id(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Reuses the existing scan ownership check (404 on miss to avoid enumeration).
    _fetch_scan_owned(scan_id, principal)

    body = body or NextStepsRequest()
    service = _get_next_steps_service()
    try:
        return service.get_next_steps(
            finding_id,
            bypass_cache=body.bypass_cache,
            model=body.model,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/scan/{scan_id}/export/pdf")
async def export_scan_pdf(scan_id: str, principal: UserPrincipal = Depends(require_user)):
    """Generate and download a PDF report for a scan."""
    scan = _fetch_scan_owned(scan_id, principal)
    from api.export import build_pdf
    buf = build_pdf(scan_id, scan)
    filename = f"vulnreach-{scan_id[:8]}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Public endpoints ─────────────────────────────────────────────

_BOOT_ID = uuid.uuid4().hex

@app.get("/health")
async def health():
    return {"status": "ok", "boot_id": _BOOT_ID}


@app.get("/tools")
async def list_tools(principal: UserPrincipal = Depends(require_user)):
    return {"available_tools": AVAILABLE_TOOLS}
