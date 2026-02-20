"""GCP cloud discovery — Vertex AI agents and Cloud Run services.

Requires ``google-cloud-aiplatform``.  Install with::

    pip install 'agent-bom[gcp]'

Authentication uses Application Default Credentials (``gcloud auth application-default login``
or ``GOOGLE_APPLICATION_CREDENTIALS`` env var).
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    project_id: str | None = None,
    region: str = "us-central1",
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Google Cloud Vertex AI and Cloud Run.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``google-cloud-aiplatform`` is not installed.
    """
    try:
        import google.cloud.aiplatform  # noqa: F401 — availability check
    except ImportError:
        raise CloudDiscoveryError(
            "google-cloud-aiplatform is required for GCP discovery. "
            "Install with: pip install 'agent-bom[gcp]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not resolved_project:
        warnings.append(
            "GOOGLE_CLOUD_PROJECT not set. Provide --gcp-project or "
            "set the GOOGLE_CLOUD_PROJECT env var."
        )
        return agents, warnings

    # ── Vertex AI Endpoints ───────────────────────────────────────────────
    try:
        vertex_agents, vertex_warns = _discover_vertex_ai(
            resolved_project, region
        )
        agents.extend(vertex_agents)
        warnings.extend(vertex_warns)
    except Exception as exc:
        warnings.append(f"Vertex AI discovery error: {exc}")

    # ── Cloud Run services ────────────────────────────────────────────────
    try:
        run_agents, run_warns = _discover_cloud_run(resolved_project, region)
        agents.extend(run_agents)
        warnings.extend(run_warns)
    except Exception as exc:
        warnings.append(f"Cloud Run discovery error: {exc}")

    return agents, warnings


def _discover_vertex_ai(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Vertex AI endpoints and their deployed models."""
    import google.cloud.aiplatform as aiplatform

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        aiplatform.init(project=project_id, location=region)
        endpoints = aiplatform.Endpoint.list()

        for endpoint in endpoints:
            ep_name = endpoint.display_name or "unknown"
            ep_resource = endpoint.resource_name

            # List deployed models on this endpoint
            servers: list[MCPServer] = []
            for deployed in endpoint.gca_resource.deployed_models:
                model_id = deployed.model
                server = MCPServer(
                    name=f"vertex-model:{deployed.display_name or model_id}",
                    command="",
                    transport=TransportType.STREAMABLE_HTTP,
                    url=f"https://{region}-aiplatform.googleapis.com/v1/{ep_resource}",
                )
                servers.append(server)

            agent = Agent(
                name=f"vertex-ai:{ep_name}",
                agent_type=AgentType.CUSTOM,
                config_path=ep_resource,
                source="gcp-vertex-ai",
                mcp_servers=servers,
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Vertex AI endpoints: {exc}")

    return agents, warnings


def _discover_cloud_run(
    project_id: str,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Cloud Run services and extract container images."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from google.cloud.run_v2 import ServicesClient
    except ImportError:
        warnings.append("google-cloud-run not installed. Skipping Cloud Run discovery.")
        return agents, warnings

    try:
        client = ServicesClient()
        parent = f"projects/{project_id}/locations/{region}"
        services = client.list_services(parent=parent)

        for service in services:
            svc_name = service.name.split("/")[-1] if service.name else "unknown"
            template = service.template
            if not template or not template.containers:
                continue

            for container in template.containers:
                image = container.image or ""
                if image:
                    server = MCPServer(
                        name=f"cloud-run:{svc_name}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                    )
                    agent = Agent(
                        name=f"cloud-run:{svc_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=service.name or f"gcp://{svc_name}",
                        source="gcp-cloud-run",
                        mcp_servers=[server],
                    )
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Cloud Run services: {exc}")

    return agents, warnings
