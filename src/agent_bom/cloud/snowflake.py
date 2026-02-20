"""Snowflake cloud discovery — Cortex agents, Cortex MCP servers, Snowpark packages.

Requires ``snowflake-connector-python``.  Install with::

    pip install 'agent-bom[snowflake]'

Authentication uses standard Snowflake connector auth (env vars SNOWFLAKE_ACCOUNT,
SNOWFLAKE_USER, SNOWFLAKE_PASSWORD, or external browser / key pair / SSO).
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex agents, MCP servers, and Snowpark packages from Snowflake.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``snowflake-connector-python`` is not installed.
    """
    try:
        import snowflake.connector  # noqa: F811
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake discovery. "
            "Install with: pip install 'agent-bom[snowflake]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT", "")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER", "")

    if not resolved_account:
        warnings.append(
            "SNOWFLAKE_ACCOUNT not set. Provide --snowflake-account or "
            "set the SNOWFLAKE_ACCOUNT env var."
        )
        return agents, warnings

    conn_kwargs: dict[str, Any] = {
        "account": resolved_account,
        "user": resolved_user,
    }
    if authenticator:
        conn_kwargs["authenticator"] = authenticator
    if database:
        conn_kwargs["database"] = database
    if schema:
        conn_kwargs["schema"] = schema

    # Try password from env if no authenticator specified
    if not authenticator:
        password = os.environ.get("SNOWFLAKE_PASSWORD", "")
        if password:
            conn_kwargs["password"] = password
        else:
            conn_kwargs["authenticator"] = "externalbrowser"

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        warnings.append(f"Could not connect to Snowflake: {exc}")
        return agents, warnings

    try:
        # ── Cortex Search Services ────────────────────────────────────────
        cortex_agents, cortex_warns = _discover_cortex_services(conn, resolved_account, database, schema)
        agents.extend(cortex_agents)
        warnings.extend(cortex_warns)

        # ── Cortex Agents (v2025 Agent framework) ─────────────────────────
        cortex_agent_list, ca_warns = _discover_cortex_agents(conn, resolved_account)
        agents.extend(cortex_agent_list)
        warnings.extend(ca_warns)

        # ── Snowflake MCP Servers (GA Nov 2025) ───────────────────────────
        mcp_agents, mcp_warns = _discover_mcp_servers(conn, resolved_account)
        agents.extend(mcp_agents)
        warnings.extend(mcp_warns)

        # ── Query History audit (supplementary) ───────────────────────────
        qh_agents, qh_warns = _discover_from_query_history(conn, resolved_account)
        agents.extend(qh_agents)
        warnings.extend(qh_warns)

        # ── Custom Tools (functions & procedures) ─────────────────────────
        custom_tools, ct_warns = _discover_custom_tools(conn, resolved_account)
        warnings.extend(ct_warns)
        # Attach to cortex agents if any, otherwise create a standalone agent
        if custom_tools and cortex_agent_list:
            for a in cortex_agent_list:
                for srv in a.mcp_servers:
                    srv.tools.extend(custom_tools)
        elif custom_tools:
            tool_server = MCPServer(
                name="snowflake-custom-tools",
                transport=TransportType.UNKNOWN,
                tools=custom_tools,
            )
            agents.append(Agent(
                name=f"snowflake-tools:{resolved_account}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{resolved_account}/custom-tools",
                source="snowflake-tools",
                mcp_servers=[tool_server],
            ))

        # ── Snowpark packages ─────────────────────────────────────────────
        snowpark_pkgs, sp_warns = _discover_snowpark_packages(conn, resolved_account)
        warnings.extend(sp_warns)

        # If we found Snowpark packages but no Cortex agents, create a generic agent
        all_cortex = cortex_agents + cortex_agent_list
        if snowpark_pkgs and not all_cortex:
            server = MCPServer(
                name="snowpark-packages",
                transport=TransportType.UNKNOWN,
                packages=snowpark_pkgs,
            )
            agent = Agent(
                name=f"snowflake:{resolved_account}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{resolved_account}",
                source="snowflake",
                mcp_servers=[server],
            )
            agents.append(agent)

        # ── Streamlit apps ────────────────────────────────────────────────
        streamlit_agents, st_warns = _discover_streamlit_apps(conn, resolved_account)
        agents.extend(streamlit_agents)
        warnings.extend(st_warns)

    finally:
        conn.close()

    return agents, warnings


def _discover_cortex_services(
    conn: Any,
    account: str,
    database: str | None,
    schema: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex Search Services and their configurations."""
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW CORTEX SEARCH SERVICES")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            service_name = row_dict.get("name", str(row[0]) if row else "unknown")
            svc_database = row_dict.get("database_name", database or "")
            svc_schema = row_dict.get("schema_name", schema or "")

            config_path = f"snowflake://{account}/{svc_database}/{svc_schema}/{service_name}"

            tools = [
                MCPTool(name="semantic_search", description="Search indexed documents"),
                MCPTool(name="document_retrieve", description="Retrieve document by ID"),
            ]

            server = MCPServer(
                name=f"cortex-search:{service_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/cortex/search/{service_name}",
                tools=tools,
            )

            agent = Agent(
                name=f"cortex:{service_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-cortex",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        # Cortex Search Services may not be available in all accounts
        warnings.append(f"Could not list Cortex Search Services: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _discover_snowpark_packages(
    conn: Any,
    account: str,
) -> tuple[list[Package], list[str]]:
    """Query INFORMATION_SCHEMA.PACKAGES for installed Snowpark Python packages."""
    packages: list[Package] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT PACKAGE_NAME, VERSION "
            "FROM INFORMATION_SCHEMA.PACKAGES "
            "WHERE LANGUAGE = 'python' "
            "ORDER BY PACKAGE_NAME"
        )
        seen: set[str] = set()
        for row in cursor.fetchall():
            name = str(row[0])
            version = str(row[1])
            if name.lower() not in seen:
                seen.add(name.lower())
                packages.append(Package(name=name, version=version, ecosystem="pypi"))

    except Exception as exc:
        # INFORMATION_SCHEMA.PACKAGES may not exist or may not be accessible
        warnings.append(f"Could not query Snowpark packages: {exc}")

    finally:
        cursor.close()

    return packages, warnings


def _discover_streamlit_apps(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Streamlit apps deployed in Snowflake."""
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW STREAMLIT IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            app_name = row_dict.get("name", str(row[0]) if row else "unknown")
            app_db = row_dict.get("database_name", "")
            app_schema = row_dict.get("schema_name", "")

            server = MCPServer(
                name=f"streamlit:{app_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/streamlit/{app_name}",
            )
            agent = Agent(
                name=f"streamlit:{app_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/{app_db}/{app_schema}/streamlit/{app_name}",
                source="snowflake-streamlit",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Streamlit apps: {exc}")

    finally:
        cursor.close()

    return agents, warnings


# ---------------------------------------------------------------------------
# Deep discovery — Cortex Agents, MCP Servers, Query History, Custom Tools
# ---------------------------------------------------------------------------


def _discover_cortex_agents(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex Agents via SHOW AGENTS IN ACCOUNT.

    The Cortex Agent framework (v2025) is distinct from Cortex Search Services.
    These are agentic orchestration systems combining semantic models, search
    services, and custom tools.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW AGENTS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            agent_name = row_dict.get("name", str(row[0]) if row else "unknown")
            db_name = row_dict.get("database_name", "")
            schema_name = row_dict.get("schema_name", "")

            # Parse profile JSON if available (contains display_name)
            profile_str = row_dict.get("profile", "")
            display_name = agent_name
            if profile_str:
                try:
                    profile = json.loads(profile_str)
                    display_name = profile.get("display_name", agent_name)
                except (json.JSONDecodeError, TypeError):
                    pass

            config_path = f"snowflake://{account}/{db_name}/{schema_name}/{agent_name}"

            server = MCPServer(
                name=f"cortex-agent:{agent_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/api/v2/cortex/agent/{agent_name}",
            )

            agent = Agent(
                name=f"cortex-agent:{display_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-cortex-agent",
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Cortex Agents: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _discover_mcp_servers(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Discover Snowflake-native MCP Servers via SHOW MCP SERVERS.

    GA since November 2025. Follows up with DESCRIBE MCP SERVER to get
    tool specifications from the YAML definition.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW MCP SERVERS IN ACCOUNT")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            server_name = row_dict.get("name", str(row[0]) if row else "unknown")
            db_name = row_dict.get("database_name", "")
            schema_name = row_dict.get("schema_name", "")

            tools = _describe_mcp_server_tools(conn, server_name, db_name, schema_name, warnings)

            fqn = f"{db_name}.{schema_name}.{server_name}" if db_name else server_name
            config_path = f"snowflake://{account}/{db_name}/{schema_name}/mcp/{server_name}"

            mcp_server = MCPServer(
                name=f"snowflake-mcp:{server_name}",
                transport=TransportType.STREAMABLE_HTTP,
                url=f"https://{account}.snowflakecomputing.com/api/v2/mcp/{fqn}",
                tools=tools,
            )

            agent = Agent(
                name=f"mcp-server:{server_name}",
                agent_type=AgentType.CUSTOM,
                config_path=config_path,
                source="snowflake-mcp",
                mcp_servers=[mcp_server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list Snowflake MCP Servers: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _describe_mcp_server_tools(
    conn: Any,
    server_name: str,
    db_name: str,
    schema_name: str,
    warnings: list[str],
) -> list[MCPTool]:
    """Run DESCRIBE MCP SERVER and parse the YAML spec for tool definitions.

    Flags SYSTEM_EXECUTE_SQL tools with a high-risk warning in the description.
    """
    tools: list[MCPTool] = []
    cursor = conn.cursor()

    try:
        fqn = f"{db_name}.{schema_name}.{server_name}" if db_name else server_name
        cursor.execute(f"DESCRIBE MCP SERVER {fqn}")
        rows = cursor.fetchall()
        columns = [desc[0].lower() for desc in cursor.description] if cursor.description else []

        for row in rows:
            row_dict = dict(zip(columns, row)) if columns else {}
            prop_name = row_dict.get("property", row_dict.get("name", ""))
            prop_value = row_dict.get("property_value", row_dict.get("value", ""))

            if "spec" in str(prop_name).lower() or "definition" in str(prop_name).lower():
                try:
                    import yaml
                    spec = yaml.safe_load(str(prop_value))
                    if isinstance(spec, dict):
                        for tool_def in spec.get("tools", []):
                            tool_name = tool_def.get("name", "unknown")
                            tool_type = tool_def.get("type", "")
                            description = tool_def.get("description", "")

                            if tool_type == "SYSTEM_EXECUTE_SQL" or "execute_sql" in tool_name.lower():
                                description = f"[HIGH-RISK: SYSTEM_EXECUTE_SQL] {description}"

                            tools.append(MCPTool(name=tool_name, description=description))
                except Exception:
                    pass

    except Exception as exc:
        warnings.append(f"Could not describe MCP Server {server_name}: {exc}")

    finally:
        cursor.close()

    return tools


def _discover_from_query_history(
    conn: Any,
    account: str,
) -> tuple[list[Agent], list[str]]:
    """Audit QUERY_HISTORY for recent CREATE AGENT / CREATE MCP SERVER statements.

    Catches objects created recently or subsequently dropped (shadow inventory).
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    cursor = conn.cursor()
    seen_names: set[str] = set()

    try:
        cursor.execute(
            "SELECT query_text, user_name, start_time "
            "FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY()) "
            "WHERE query_text ILIKE '%CREATE%MCP SERVER%' "
            "   OR query_text ILIKE '%CREATE%AGENT%' "
            "ORDER BY start_time DESC "
            "LIMIT 100"
        )
        rows = cursor.fetchall()

        for row in rows:
            query_text = str(row[0]) if row else ""

            obj_name = _parse_create_statement_name(query_text)
            if not obj_name or obj_name in seen_names:
                continue
            seen_names.add(obj_name)

            is_mcp = "MCP SERVER" in query_text.upper()
            source = "snowflake-mcp-audit" if is_mcp else "snowflake-agent-audit"
            obj_type = "mcp-server" if is_mcp else "agent"

            server = MCPServer(
                name=f"audit:{obj_type}:{obj_name}",
                transport=TransportType.UNKNOWN,
            )
            agent = Agent(
                name=f"audit:{obj_type}:{obj_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/query-history/{obj_name}",
                source=source,
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not query Snowflake query history: {exc}")

    finally:
        cursor.close()

    return agents, warnings


def _parse_create_statement_name(query_text: str) -> str | None:
    """Extract the object name from a CREATE AGENT or CREATE MCP SERVER SQL statement."""
    cleaned = " ".join(query_text.split())
    pattern = r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:AGENT|MCP\s+SERVER)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)"
    match = re.search(pattern, cleaned, re.IGNORECASE)
    if match:
        name = match.group(1).strip('"')
        return name.split(".")[-1]
    return None


def _discover_custom_tools(
    conn: Any,
    account: str,
) -> tuple[list[MCPTool], list[str]]:
    """Discover user-defined functions and procedures that serve as custom tools.

    The language (Python/Java/SQL/JavaScript) is noted in the description
    because it affects the attack surface.
    """
    tools: list[MCPTool] = []
    warnings: list[str] = []

    # Query functions
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT function_name, argument_signature, data_type, function_language "
            "FROM INFORMATION_SCHEMA.FUNCTIONS "
            "WHERE function_schema NOT IN ('INFORMATION_SCHEMA') "
            "ORDER BY function_name "
            "LIMIT 500"
        )
        for row in cursor.fetchall():
            func_name = str(row[0]) if row else "unknown"
            arg_sig = str(row[1]) if len(row) > 1 else ""
            return_type = str(row[2]) if len(row) > 2 else ""
            language = str(row[3]) if len(row) > 3 else "SQL"

            risk_note = ""
            if language.upper() in ("PYTHON", "JAVA", "JAVASCRIPT"):
                risk_note = f" [external runtime: {language}]"

            tools.append(MCPTool(
                name=func_name,
                description=f"UDF({arg_sig}) -> {return_type} [{language}]{risk_note}",
            ))
    except Exception as exc:
        warnings.append(f"Could not query custom functions: {exc}")
    finally:
        cursor.close()

    # Query procedures
    proc_cursor = conn.cursor()
    try:
        proc_cursor.execute(
            "SELECT procedure_name, argument_signature, data_type, procedure_language "
            "FROM INFORMATION_SCHEMA.PROCEDURES "
            "WHERE procedure_schema NOT IN ('INFORMATION_SCHEMA') "
            "ORDER BY procedure_name "
            "LIMIT 500"
        )
        for row in proc_cursor.fetchall():
            proc_name = str(row[0]) if row else "unknown"
            arg_sig = str(row[1]) if len(row) > 1 else ""
            return_type = str(row[2]) if len(row) > 2 else ""
            language = str(row[3]) if len(row) > 3 else "SQL"

            risk_note = ""
            if language.upper() in ("PYTHON", "JAVA", "JAVASCRIPT"):
                risk_note = f" [external runtime: {language}]"

            tools.append(MCPTool(
                name=proc_name,
                description=f"PROCEDURE({arg_sig}) -> {return_type} [{language}]{risk_note}",
            ))
    except Exception as exc:
        warnings.append(f"Could not query stored procedures: {exc}")
    finally:
        proc_cursor.close()

    return tools, warnings
