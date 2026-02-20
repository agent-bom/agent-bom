"""Graph data builders for agent → server → package → CVE relationship visualization.

Produces Cytoscape.js-compatible element lists consumable by:
- The built-in HTML dashboard (``--format html``)
- Standalone graph JSON export (``--format graph``)
- External tools: Cytoscape desktop, Sigma.js, D3.js, Gephi (via conversion)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


def build_graph_elements(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    include_cve_nodes: bool = True,
) -> list[dict]:
    """Build a Cytoscape.js-compatible element list with provider, agent, server, package, and CVE nodes.

    Node types:
      - ``provider``    — cloud source grouping (AWS, Azure, Databricks, local, etc.)
      - ``agent``       — AI agent
      - ``server_vuln`` — MCP server with vulnerable packages
      - ``server_cred`` — MCP server with exposed credentials
      - ``server_clean``— MCP server, no issues
      - ``pkg_vuln``    — vulnerable package
      - ``cve``         — individual CVE/advisory

    Edge types (in ``data.type``):
      - ``hosts``       — provider → agent
      - ``uses``        — agent → server
      - ``depends_on``  — server → package
      - ``affects``     — package → CVE
    """
    elements: list[dict] = []
    vuln_pkg_keys: set[tuple[str, str]] = {
        (br.package.name, br.package.ecosystem) for br in blast_radii
    }

    # Track which provider nodes we've already created
    providers_seen: set[str] = set()

    # Map (pkg_name, ecosystem) → set of CVE IDs already added as nodes
    cve_nodes_seen: set[str] = set()

    # Build a lookup: (pkg_name, ecosystem) → list of vulnerability IDs
    pkg_to_vulns: dict[tuple[str, str], list[dict]] = {}
    for br in blast_radii:
        key = (br.package.name, br.package.ecosystem)
        if key not in pkg_to_vulns:
            pkg_to_vulns[key] = []
        pkg_to_vulns[key].append({
            "id": br.vulnerability.id,
            "severity": br.vulnerability.severity.value,
            "summary": br.vulnerability.summary[:100] if br.vulnerability.summary else "",
            "risk_score": br.risk_score,
        })

    for agent in report.agents:
        # ── Provider node ─────────────────────────────────────────────
        source = agent.source or "local"
        if source not in providers_seen:
            providers_seen.add(source)
            elements.append({"data": {
                "id": f"provider:{source}",
                "label": _provider_label(source),
                "type": "provider",
                "tip": f"Source: {source}",
            }})

        # ── Agent node ────────────────────────────────────────────────
        aid = f"a:{agent.name}"
        elements.append({"data": {
            "id": aid,
            "label": agent.name,
            "type": "agent",
            "tip": (
                f"Agent: {agent.name}\n"
                f"Type: {agent.agent_type.value}\n"
                f"Source: {source}\n"
                f"Servers: {len(agent.mcp_servers)}"
            ),
        }})
        # Edge: provider → agent
        elements.append({"data": {
            "source": f"provider:{source}",
            "target": aid,
            "type": "hosts",
        }})

        # ── Server nodes ──────────────────────────────────────────────
        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            vuln_count = sum(
                1 for p in srv.packages
                if (p.name, p.ecosystem) in vuln_pkg_keys
            )
            has_vuln = vuln_count > 0
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")

            pkg_note = f"\nPackages: {len(srv.packages)}"
            if vuln_count:
                pkg_note += f"\nVulnerable: {vuln_count}"
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f" ({len(srv.packages)})"

            elements.append({"data": {
                "id": sid,
                "label": srv.name + pkg_badge,
                "type": stype,
                "tip": f"MCP Server: {srv.name}{pkg_note}{cinfo}",
            }})
            # Edge: agent → server
            elements.append({"data": {
                "source": aid,
                "target": sid,
                "type": "uses",
            }})

            # ── Package nodes (vulnerable only) ───────────────────────
            seen_pkg_ids: set[str] = set()
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                if pkg_key not in vuln_pkg_keys:
                    continue

                pid = f"pkg:{pkg.name}:{pkg.ecosystem}"
                if pid in seen_pkg_ids:
                    # Just add another edge for shared package
                    elements.append({"data": {
                        "source": sid,
                        "target": pid,
                        "type": "depends_on",
                    }})
                    continue
                seen_pkg_ids.add(pid)

                vc = len(pkg.vulnerabilities)
                elements.append({"data": {
                    "id": pid,
                    "label": f"{pkg.name}\n{pkg.version}",
                    "type": "pkg_vuln",
                    "tip": (
                        f"Package: {pkg.name}\n"
                        f"Version: {pkg.version}\n"
                        f"Ecosystem: {pkg.ecosystem}\n"
                        f"Vulnerabilities: {vc if vc else '(via blast radius)'}"
                    ),
                }})
                # Edge: server → package
                elements.append({"data": {
                    "source": sid,
                    "target": pid,
                    "type": "depends_on",
                }})

                # ── CVE nodes ─────────────────────────────────────────
                if include_cve_nodes and pkg_key in pkg_to_vulns:
                    for vuln_info in pkg_to_vulns[pkg_key]:
                        cve_id = f"cve:{vuln_info['id']}"
                        if cve_id not in cve_nodes_seen:
                            cve_nodes_seen.add(cve_id)
                            sev = vuln_info["severity"]
                            elements.append({"data": {
                                "id": cve_id,
                                "label": vuln_info["id"],
                                "type": f"cve_{sev}",
                                "tip": (
                                    f"{vuln_info['id']}\n"
                                    f"Severity: {sev}\n"
                                    f"{vuln_info['summary']}"
                                ),
                            }})
                        # Edge: package → CVE
                        elements.append({"data": {
                            "source": pid,
                            "target": cve_id,
                            "type": "affects",
                        }})

    return elements


def _provider_label(source: str) -> str:
    """Human-readable label for a provider source string."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "aws-sagemaker": "AWS SageMaker",
        "azure-container-apps": "Azure Container Apps",
        "azure-ai-foundry": "Azure AI Foundry",
        "gcp-vertex-ai": "GCP Vertex AI",
        "gcp-cloud-run": "GCP Cloud Run",
        "databricks": "Databricks",
        "snowflake-cortex": "Snowflake Cortex",
        "snowflake-streamlit": "Snowflake Streamlit",
        "snowflake": "Snowflake",
    }
    return labels.get(source, source.upper())
