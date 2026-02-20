"""Nebius cloud discovery — GPU cloud AI workloads (K8s clusters, container services).

Requires ``nebius``.  Install with::

    pip install 'agent-bom[nebius]'

Authentication uses Nebius credentials (NEBIUS_API_KEY env var or service account).
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    api_key: str | None = None,
    project_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI workloads from Nebius GPU cloud.

    Discovers Managed K8s clusters and container services. For K8s clusters,
    deeper scanning can be done with ``--k8s --context=<cluster>``.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``nebius`` is not installed.
    """
    try:
        import nebius  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "nebius is required for Nebius discovery. "
            "Install with: pip install 'agent-bom[nebius]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_key = api_key or os.environ.get("NEBIUS_API_KEY", "")
    resolved_project = project_id or os.environ.get("NEBIUS_PROJECT_ID", "")

    if not resolved_key:
        warnings.append(
            "NEBIUS_API_KEY not set. Provide --nebius-api-key or "
            "set the NEBIUS_API_KEY env var."
        )
        return agents, warnings

    if not resolved_project:
        warnings.append(
            "NEBIUS_PROJECT_ID not set. Provide --nebius-project-id or "
            "set the NEBIUS_PROJECT_ID env var."
        )
        return agents, warnings

    # ── Managed K8s clusters ─────────────────────────────────────────────
    try:
        k8s_agents, k8s_warns = _discover_k8s_clusters(resolved_key, resolved_project)
        agents.extend(k8s_agents)
        warnings.extend(k8s_warns)
    except Exception as exc:
        warnings.append(f"Nebius K8s discovery error: {exc}")

    # ── Container services ───────────────────────────────────────────────
    try:
        cs_agents, cs_warns = _discover_container_services(resolved_key, resolved_project)
        agents.extend(cs_agents)
        warnings.extend(cs_warns)
    except Exception as exc:
        warnings.append(f"Nebius container service discovery error: {exc}")

    return agents, warnings


def _discover_k8s_clusters(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Nebius Managed Kubernetes clusters."""
    import nebius

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = nebius.Client(api_key=api_key)
        clusters = client.kubernetes.clusters.list(project_id=project_id)

        for cluster in clusters:
            cluster_id = getattr(cluster, "id", "unknown")
            cluster_name = getattr(cluster, "name", cluster_id)
            cluster_status = getattr(cluster, "status", "UNKNOWN")

            server = MCPServer(
                name=f"nebius-k8s:{cluster_name}",
                transport=TransportType.UNKNOWN,
                env={"NEBIUS_CLUSTER_ID": cluster_id},
            )

            agent = Agent(
                name=f"nebius-k8s:{cluster_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"nebius://{project_id}/k8s/{cluster_id}",
                source="nebius-k8s",
                version=str(cluster_status),
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Nebius K8s clusters: {exc}")

    return agents, warnings


def _discover_container_services(
    api_key: str,
    project_id: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Nebius container services and their images."""
    import nebius

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = nebius.Client(api_key=api_key)

        if not hasattr(client, "containers"):
            return agents, warnings

        services = client.containers.services.list(project_id=project_id)

        for svc in services:
            svc_id = getattr(svc, "id", "unknown")
            svc_name = getattr(svc, "name", svc_id)
            image = getattr(svc, "image", "")

            if image:
                server = MCPServer(
                    name=f"nebius-container:{svc_name}",
                    command="docker",
                    args=["run", str(image)],
                    transport=TransportType.STDIO,
                )
            else:
                server = MCPServer(
                    name=f"nebius-container:{svc_name}",
                    transport=TransportType.UNKNOWN,
                )

            agent = Agent(
                name=f"nebius-container:{svc_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"nebius://{project_id}/containers/{svc_id}",
                source="nebius-container",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Nebius container services: {exc}")

    return agents, warnings
