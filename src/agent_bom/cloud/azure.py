"""Azure cloud discovery — AI Foundry agents and Container Apps.

Requires ``azure-identity`` and related SDKs.  Install with::

    pip install 'agent-bom[azure]'

Authentication uses ``DefaultAzureCredential`` (env vars, managed identity,
Azure CLI login, VS Code credentials).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    subscription_id: str | None = None,
    resource_group: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Azure AI Foundry and Container Apps.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``azure-identity`` is not installed.
    """
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F811
    except ImportError:
        raise CloudDiscoveryError(
            "azure-identity is required for Azure discovery. "
            "Install with: pip install 'agent-bom[azure]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not resolved_sub:
        warnings.append(
            "AZURE_SUBSCRIPTION_ID not set. Provide --azure-subscription or "
            "set the AZURE_SUBSCRIPTION_ID env var."
        )
        return agents, warnings

    try:
        credential = DefaultAzureCredential()
    except Exception as exc:
        warnings.append(f"Azure authentication failed: {exc}")
        return agents, warnings

    # ── Container Apps ────────────────────────────────────────────────────
    try:
        container_agents, ca_warns = _discover_container_apps(
            credential, resolved_sub, resource_group
        )
        agents.extend(container_agents)
        warnings.extend(ca_warns)
    except Exception as exc:
        warnings.append(f"Azure Container Apps discovery error: {exc}")

    # ── AI Foundry agents ─────────────────────────────────────────────────
    try:
        ai_agents, ai_warns = _discover_ai_foundry(credential, resolved_sub, resource_group)
        agents.extend(ai_agents)
        warnings.extend(ai_warns)
    except Exception as exc:
        warnings.append(f"Azure AI Foundry discovery error: {exc}")

    return agents, warnings


def _discover_container_apps(
    credential: Any,
    subscription_id: str,
    resource_group: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure Container Apps and extract their container images."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.mgmt.appcontainers import ContainerAppsAPIClient
    except ImportError:
        warnings.append("azure-mgmt-appcontainers not installed. Skipping Container Apps discovery.")
        return agents, warnings

    try:
        client = ContainerAppsAPIClient(credential, subscription_id)

        if resource_group:
            apps = list(client.container_apps.list_by_resource_group(resource_group))
        else:
            apps = list(client.container_apps.list_by_subscription())

        for app in apps:
            app_name = app.name or "unknown"
            template = getattr(app, "template", None)
            if not template:
                continue

            containers = getattr(template, "containers", []) or []
            for container in containers:
                image = getattr(container, "image", "")
                if image:
                    server = MCPServer(
                        name=f"container:{container.name or image}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                    )
                    agent = Agent(
                        name=f"azure-container-app:{app_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=app.id or f"azure://{app_name}",
                        source="azure-container-apps",
                        mcp_servers=[server],
                    )
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Container Apps: {exc}")

    return agents, warnings


def _discover_ai_foundry(
    credential: Any,
    subscription_id: str,
    resource_group: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Azure AI Foundry (Azure AI Studio) agents."""
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from azure.ai.projects import AIProjectClient  # noqa: F401 — availability check
    except ImportError:
        warnings.append(
            "azure-ai-projects not installed. Skipping AI Foundry agent discovery. "
            "Install with: pip install azure-ai-projects"
        )
        return agents, warnings

    # AI Foundry requires a project endpoint — discover via resource graph
    try:
        from azure.mgmt.resource import ResourceManagementClient
        rm_client = ResourceManagementClient(credential, subscription_id)

        # Find AI project resources
        filter_str = "resourceType eq 'Microsoft.MachineLearningServices/workspaces'"
        if resource_group:
            resources = list(rm_client.resources.list_by_resource_group(
                resource_group, filter=filter_str
            ))
        else:
            resources = list(rm_client.resources.list(filter=filter_str))

        for resource in resources:
            ws_name = resource.name or "unknown"
            agent = Agent(
                name=f"azure-ai-foundry:{ws_name}",
                agent_type=AgentType.CUSTOM,
                config_path=resource.id or f"azure://{ws_name}",
                source="azure-ai-foundry",
                mcp_servers=[],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not discover AI Foundry workspaces: {exc}")

    return agents, warnings
