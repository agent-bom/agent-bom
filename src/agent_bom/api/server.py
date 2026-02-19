"""agent-bom FastAPI server.

Start with:
    agent-bom api                      # default: http://localhost:8422
    agent-bom api --host 0.0.0.0 --port 8422

Endpoints:
    GET  /                             redirect → /docs
    GET  /health                       liveness probe
    GET  /version                      version info
    POST /v1/scan                      start a scan (async, returns job_id)
    GET  /v1/scan/{job_id}             poll scan status + results
    GET  /v1/scan/{job_id}/stream      SSE — real-time scan progress
    GET  /v1/agents                    quick agent discovery (no CVE scan)
    DELETE /v1/scan/{job_id}           cancel / discard a job
"""

from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "agent-bom API requires extra dependencies.\n"
        "Install with:  pip install 'agent-bom[api]'"
    ) from exc

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="agent-bom API",
    description=(
        "AI Bill of Materials — map the full trust chain from AI agents and "
        "MCP servers to CVEs, credentials, and blast radius."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production with specific UI origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Thread pool for running blocking scan functions without blocking the event loop
_executor = ThreadPoolExecutor(max_workers=4)

# In-memory job store  {job_id: ScanJob}
_jobs: dict[str, "ScanJob"] = {}


# ─── Models ───────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRequest(BaseModel):
    """Options accepted by POST /v1/scan — mirrors agent-bom scan CLI flags."""

    inventory: str | None = None
    """Path to agents.json inventory file."""

    images: list[str] = []
    """Docker image references to scan (e.g. ['myapp:latest', 'redis:7'])."""

    k8s: bool = False
    """Scan running Kubernetes pods via kubectl."""

    k8s_namespace: str | None = None
    """Kubernetes namespace (None = all)."""

    tf_dirs: list[str] = []
    """Terraform directories to scan."""

    gha_path: str | None = None
    """Path to a Git repo to scan GitHub Actions workflows."""

    agent_projects: list[str] = []
    """Python project directories using AI agent frameworks."""

    sbom: str | None = None
    """Path to an existing CycloneDX / SPDX SBOM file."""

    enrich: bool = False
    """Enrich with NVD CVSS, EPSS, and CISA KEV data."""

    format: str = "json"
    """Output format: json | cyclonedx | sarif | spdx | html | text."""


class ScanJob(BaseModel):
    """Represents a running or completed scan job."""

    job_id: str
    status: JobStatus = JobStatus.PENDING
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    request: ScanRequest
    progress: list[str] = []
    result: dict[str, Any] | None = None
    error: str | None = None

    model_config = {"arbitrary_types_allowed": True}


class VersionInfo(BaseModel):
    version: str
    api_version: str = "v1"
    python_package: str = "agent-bom"


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_scan_sync(job: ScanJob) -> None:
    """Run the full scan pipeline in a thread (blocking). Updates job in-place."""
    import json as _json

    job.status = JobStatus.RUNNING
    job.started_at = _now()
    job.progress.append("Starting scan...")

    try:
        from agent_bom.output import to_json
        from agent_bom.scanner import scan_agents

        req = job.request
        agents = []
        warnings_all: list[str] = []

        # Step 1 — auto-discover local MCP configs
        job.progress.append("Discovering local MCP configurations...")
        local_agents, local_warnings = scan_agents()
        agents.extend(local_agents)
        warnings_all.extend(local_warnings)

        # Step 2 — inventory file
        if req.inventory:
            job.progress.append(f"Loading inventory: {req.inventory}")
            from agent_bom.inventory import load_inventory
            inv_agents, inv_warnings = load_inventory(req.inventory)
            agents.extend(inv_agents)
            warnings_all.extend(inv_warnings)

        # Step 3 — Docker images
        for image in req.images:
            job.progress.append(f"Scanning image: {image}")
            from agent_bom.image_scanner import scan_image
            img_agents, img_warnings = scan_image(image)
            agents.extend(img_agents)
            warnings_all.extend(img_warnings)

        # Step 4 — Kubernetes
        if req.k8s:
            job.progress.append("Scanning Kubernetes pods...")
            from agent_bom.k8s_scanner import scan_k8s
            k8s_agents, k8s_warnings = scan_k8s(namespace=req.k8s_namespace)
            agents.extend(k8s_agents)
            warnings_all.extend(k8s_warnings)

        # Step 5 — Terraform
        for tf_dir in req.tf_dirs:
            job.progress.append(f"Scanning Terraform: {tf_dir}")
            from agent_bom.terraform import scan_terraform
            tf_agents, tf_warnings = scan_terraform(tf_dir)
            agents.extend(tf_agents)
            warnings_all.extend(tf_warnings)

        # Step 6 — GitHub Actions
        if req.gha_path:
            job.progress.append(f"Scanning GitHub Actions: {req.gha_path}")
            from agent_bom.github_actions import scan_github_actions
            gha_agents, gha_warnings = scan_github_actions(req.gha_path)
            agents.extend(gha_agents)
            warnings_all.extend(gha_warnings)

        # Step 7 — Python agent projects
        for ap in req.agent_projects:
            job.progress.append(f"Scanning Python agent project: {ap}")
            from agent_bom.python_agents import scan_python_agents
            py_agents, py_warnings = scan_python_agents(ap)
            agents.extend(py_agents)
            warnings_all.extend(py_warnings)

        # Step 8 — existing SBOM
        if req.sbom:
            job.progress.append(f"Ingesting SBOM: {req.sbom}")
            from agent_bom.sbom_ingest import ingest_sbom
            sbom_agents, sbom_warnings = ingest_sbom(req.sbom)
            agents.extend(sbom_agents)
            warnings_all.extend(sbom_warnings)

        if not agents:
            job.progress.append("No agents found.")
            job.result = {"agents": [], "vulnerabilities": [], "blast_radius": [], "warnings": warnings_all}
            job.status = JobStatus.DONE
            job.completed_at = _now()
            return

        job.progress.append(f"Found {len(agents)} agent(s). Querying OSV.dev for CVEs...")

        # Step 9 — CVE scan
        from agent_bom.scanner import scan_vulnerabilities
        report = scan_vulnerabilities(agents, enrich=req.enrich)

        if req.enrich:
            job.progress.append("Enriching with NVD CVSS, EPSS, CISA KEV...")

        job.progress.append("Computing blast radius...")

        # Return JSON-serialisable report
        report_json = _json.loads(to_json(report))
        report_json["warnings"] = warnings_all
        job.result = report_json
        job.status = JobStatus.DONE
        job.progress.append("Scan complete.")

    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.FAILED
        job.error = str(exc)
        job.progress.append(f"Error: {exc}")
    finally:
        job.completed_at = _now()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(status="ok", version=__version__)


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


@app.post("/v1/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.
    """
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        created_at=_now(),
        request=request,
    )
    _jobs[job.job_id] = job

    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_scan_sync, job)

    return job


@app.get("/v1/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(job_id: str) -> ScanJob:
    """Poll scan status and results."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return _jobs[job_id]


@app.delete("/v1/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(job_id: str) -> None:
    """Discard a job record."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    del _jobs[job_id]


@app.get("/v1/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(job_id: str):
    """Server-Sent Events stream for real-time scan progress.

    Connect with EventSource:
        const es = new EventSource('/v1/scan/{job_id}/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    try:
        from sse_starlette.sse import EventSourceResponse
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="SSE requires sse-starlette. Install: pip install 'agent-bom[api]'",
        ) from exc

    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    import json as _json

    async def event_generator():
        job = _jobs[job_id]
        sent = 0
        while True:
            current = _jobs.get(job_id)
            if current is None:
                break
            # Send any new progress lines
            for line in current.progress[sent:]:
                yield {"data": _json.dumps({"type": "progress", "message": line})}
                sent += 1
            if current.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": current.status, "job_id": job_id})}
                break
            await asyncio.sleep(0.25)

    return EventSourceResponse(event_generator())


@app.get("/v1/agents", tags=["discovery"])
async def list_agents() -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        from agent_bom.scanner import scan_agents
        agents, warnings = scan_agents()
        return {
            "agents": [a.model_dump() for a in agents],
            "count": len(agents),
            "warnings": warnings,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/jobs", tags=["scan"])
async def list_jobs() -> dict:
    """List all scan jobs (for the UI job history panel)."""
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "status": j.status,
                "created_at": j.created_at,
                "completed_at": j.completed_at,
            }
            for j in _jobs.values()
        ],
        "count": len(_jobs),
    }
