"""Tests for cloud provider auto-discovery and graph output."""

import importlib
import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cloud import CloudDiscoveryError, discover_from_provider
from agent_bom.cloud.base import CloudDiscoveryError as BaseCloudError
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _install_mock_boto3():
    """Install a mock boto3/botocore in sys.modules so we can patch it.

    Returns the SAME module objects on repeated calls so exception classes
    match across test functions.
    """
    if "botocore.exceptions" in sys.modules and hasattr(sys.modules["botocore.exceptions"], "NoCredentialsError"):
        botocore_exc = sys.modules["botocore.exceptions"]
        boto3 = sys.modules["boto3"]
        return boto3, botocore_exc

    botocore = types.ModuleType("botocore")
    botocore_exc = types.ModuleType("botocore.exceptions")

    class _NoCredentialsError(Exception):
        pass

    class _ClientError(Exception):
        def __init__(self, error_response, operation_name):
            self.response = error_response
            self.operation_name = operation_name
            msg = error_response.get("Error", {}).get("Message", "")
            super().__init__(msg)

    botocore_exc.NoCredentialsError = _NoCredentialsError
    botocore_exc.ClientError = _ClientError
    botocore.exceptions = botocore_exc

    boto3 = types.ModuleType("boto3")
    boto3.Session = MagicMock

    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = botocore_exc
    sys.modules["boto3"] = boto3

    return boto3, botocore_exc


def _install_mock_databricks():
    """Install a mock databricks-sdk in sys.modules."""
    databricks = types.ModuleType("databricks")
    databricks_sdk = types.ModuleType("databricks.sdk")
    databricks_sdk_errors = types.ModuleType("databricks.sdk.errors")

    class _PermissionDeniedError(Exception):
        pass

    databricks_sdk_errors.PermissionDenied = _PermissionDeniedError
    databricks_sdk.WorkspaceClient = MagicMock
    databricks_sdk.errors = databricks_sdk_errors
    databricks.sdk = databricks_sdk

    sys.modules.setdefault("databricks", databricks)
    sys.modules.setdefault("databricks.sdk", databricks_sdk)
    sys.modules.setdefault("databricks.sdk.errors", databricks_sdk_errors)

    return databricks_sdk


def _install_mock_snowflake():
    """Install a mock snowflake-connector-python in sys.modules."""
    snowflake = types.ModuleType("snowflake")
    snowflake_connector = types.ModuleType("snowflake.connector")
    snowflake_connector_errors = types.ModuleType("snowflake.connector.errors")

    class _DatabaseError(Exception):
        pass

    snowflake_connector_errors.DatabaseError = _DatabaseError
    snowflake_connector.connect = MagicMock
    snowflake_connector.errors = snowflake_connector_errors
    snowflake.connector = snowflake_connector

    sys.modules.setdefault("snowflake", snowflake)
    sys.modules.setdefault("snowflake.connector", snowflake_connector)
    sys.modules.setdefault("snowflake.connector.errors", snowflake_connector_errors)

    return snowflake_connector


# ─── Cloud Aggregator Tests ──────────────────────────────────────────────────


def test_discover_from_provider_unknown():
    """Unknown provider raises ValueError with available provider list."""
    with pytest.raises(ValueError, match="Unknown cloud provider"):
        discover_from_provider("oracle")


def test_cloud_discovery_error_is_base():
    """CloudDiscoveryError imported from __init__ and base are the same."""
    assert CloudDiscoveryError is BaseCloudError


# ─── AWS Provider Tests ──────────────────────────────────────────────────────


def test_aws_missing_boto3():
    """Helpful error when boto3 is not installed."""
    with patch.dict(sys.modules, {"boto3": None, "botocore": None, "botocore.exceptions": None}):
        import agent_bom.cloud.aws as aws_mod
        try:
            importlib.reload(aws_mod)
        except Exception:
            pass
        with pytest.raises(CloudDiscoveryError, match="boto3 is required"):
            from agent_bom.cloud.aws import discover
            discover()


def test_aws_bedrock_agents_discovered():
    """Bedrock agents are converted to Agent objects with correct ARN."""
    mock_boto3, _ = _install_mock_boto3()

    mock_session = MagicMock()
    mock_bedrock = MagicMock()

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"agentSummaries": [
            {"agentId": "ABC123", "agentName": "prod-agent", "agentStatus": "PREPARED"}
        ]}
    ]
    mock_ag_paginator = MagicMock()
    mock_ag_paginator.paginate.return_value = [{"actionGroupSummaries": []}]

    mock_bedrock.get_paginator.side_effect = lambda op: {
        "list_agents": mock_paginator,
        "list_agent_action_groups": mock_ag_paginator,
    }[op]
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentId": "ABC123", "agentName": "prod-agent",
            "agentArn": "arn:aws:bedrock:us-east-1:123456:agent/ABC123",
            "foundationModel": "anthropic.claude-3-sonnet", "agentStatus": "PREPARED",
        }
    }

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]
    mock_session.region_name = "us-east-1"

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1")

    assert len(agents) >= 1
    bedrock_agents = [a for a in agents if a.source == "aws-bedrock"]
    assert len(bedrock_agents) == 1
    assert bedrock_agents[0].name == "bedrock:prod-agent"
    assert "arn:aws:bedrock" in bedrock_agents[0].config_path
    assert bedrock_agents[0].agent_type == AgentType.CUSTOM


def test_aws_no_credentials_returns_warning():
    """NoCredentialsError becomes a warning, not an unhandled exception."""
    _, botocore_exc = _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = botocore_exc.NoCredentialsError()
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_bedrock

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover()

    assert agents == []
    assert any("credentials" in w.lower() for w in warnings)


def test_aws_access_denied_returns_warning():
    """AccessDeniedException returns IAM hint, not a crash."""
    _, botocore_exc = _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = botocore_exc.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListAgents",
    )
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover()

    assert any("access denied" in w.lower() or "bedrockagentreadonly" in w.lower() for w in warnings)


def test_aws_ecs_images_collected():
    """ECS tasks produce agent objects with container image refs."""
    _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_bedrock.get_paginator.return_value = mock_paginator

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/prod"]}
    mock_ecs.list_tasks.return_value = {"taskArns": ["arn:aws:ecs:us-east-1:123:task/prod/abc"]}
    mock_ecs.describe_tasks.return_value = {
        "tasks": [{"containers": [{"image": "123456.dkr.ecr.us-east-1.amazonaws.com/ml-model:latest"}]}]
    }
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1")

    ecs_agents = [a for a in agents if a.source == "aws-ecs"]
    assert len(ecs_agents) == 1
    assert "ml-model" in ecs_agents[0].name


# ─── Databricks Provider Tests ───────────────────────────────────────────────


def test_databricks_missing_sdk():
    """Helpful error when databricks-sdk is not installed."""
    with patch.dict(sys.modules, {"databricks": None, "databricks.sdk": None, "databricks.sdk.errors": None}):
        with pytest.raises(CloudDiscoveryError, match="databricks-sdk is required"):
            import agent_bom.cloud.databricks as db_mod
            importlib.reload(db_mod)
            db_mod.discover()


def test_databricks_cluster_packages():
    """PyPI libraries on a cluster become Package objects with correct ecosystem."""
    _install_mock_databricks()

    mock_ws = MagicMock()
    cluster = MagicMock()
    cluster.cluster_id = "cluster-123"
    cluster.cluster_name = "ml-cluster"
    cluster.state = "RUNNING"
    mock_ws.clusters.list.return_value = [cluster]

    lib1 = MagicMock()
    lib1.library.pypi = MagicMock(package="langchain==0.1.0")
    lib1.library.maven = None
    lib1.library.jar = None
    lib2 = MagicMock()
    lib2.library.pypi = MagicMock(package="openai==1.12.0")
    lib2.library.maven = None
    lib2.library.jar = None
    status = MagicMock()
    status.library_statuses = [lib1, lib2]
    mock_ws.libraries.cluster_status.return_value = status
    mock_ws.serving_endpoints.list.return_value = []

    with patch("databricks.sdk.WorkspaceClient", return_value=mock_ws):
        importlib.reload(importlib.import_module("agent_bom.cloud.databricks"))
        from agent_bom.cloud.databricks import discover
        agents, warnings = discover(host="https://my.databricks.com", token="fake")

    assert len(agents) == 1
    server = agents[0].mcp_servers[0]
    pkg_names = {p.name for p in server.packages}
    assert "langchain" in pkg_names
    assert "openai" in pkg_names
    assert all(p.ecosystem == "pypi" for p in server.packages)
    assert agents[0].source == "databricks"


def test_databricks_maven_packages():
    """Maven coordinates produce Package objects with ecosystem='maven'."""
    from agent_bom.cloud.databricks import _parse_maven_coords

    pkg = _parse_maven_coords("org.apache.spark:spark-sql_2.12:3.5.0")
    assert pkg is not None
    assert pkg.name == "org.apache.spark:spark-sql_2.12"
    assert pkg.version == "3.5.0"
    assert pkg.ecosystem == "maven"


def test_databricks_pypi_spec_parsing():
    """Various PyPI spec formats are parsed correctly."""
    from agent_bom.cloud.databricks import _parse_pypi_spec

    pkg = _parse_pypi_spec("langchain==0.1.0")
    assert pkg.name == "langchain"
    assert pkg.version == "0.1.0"

    pkg2 = _parse_pypi_spec("openai>=1.0")
    assert pkg2.name == "openai"
    assert pkg2.version == "1.0"

    pkg3 = _parse_pypi_spec("torch")
    assert pkg3.name == "torch"
    assert pkg3.version == "unknown"


# ─── Snowflake Provider Tests ────────────────────────────────────────────────


def test_snowflake_missing_connector():
    """Helpful error when snowflake-connector-python is not installed."""
    with patch.dict(sys.modules, {"snowflake": None, "snowflake.connector": None, "snowflake.connector.errors": None}):
        with pytest.raises(CloudDiscoveryError, match="snowflake-connector-python is required"):
            import agent_bom.cloud.snowflake as sf_mod
            importlib.reload(sf_mod)
            sf_mod.discover()


def test_snowflake_cortex_agents():
    """Cortex Search Services are discovered as agents."""
    mock_sf = _install_mock_snowflake()

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.description = [("name",), ("database_name",), ("schema_name",)]
    mock_cursor.fetchall.side_effect = [
        [("my-search-service", "MY_DB", "PUBLIC")],  # Cortex
        [],  # Snowpark
        [],  # Streamlit
    ]

    with patch.object(mock_sf, "connect", return_value=mock_conn):
        importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
        from agent_bom.cloud.snowflake import discover
        agents, warnings = discover(account="myorg.us-east-1", user="test_user")

    cortex_agents = [a for a in agents if a.source == "snowflake-cortex"]
    assert len(cortex_agents) == 1
    assert cortex_agents[0].name == "cortex:my-search-service"
    assert "snowflake://" in cortex_agents[0].config_path


def test_snowflake_snowpark_packages():
    """Snowpark packages extracted via _discover_snowpark_packages."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_snowpark_packages

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = [
        ("pandas", "2.0.3"),
        ("numpy", "1.24.0"),
        ("scikit-learn", "1.3.0"),
    ]

    packages, warnings = _discover_snowpark_packages(mock_conn, "myorg.us-east-1")

    assert len(packages) == 3
    pkg_names = {p.name for p in packages}
    assert "pandas" in pkg_names
    assert "numpy" in pkg_names
    assert "scikit-learn" in pkg_names
    assert all(p.ecosystem == "pypi" for p in packages)


# ─── Graph Output Tests ──────────────────────────────────────────────────────


def _make_sample_report():
    """Build a small report for graph tests."""
    vuln = Vulnerability(id="CVE-2024-1234", summary="Test vuln", severity=Severity.HIGH)
    pkg = Package(name="express", version="4.18.0", ecosystem="npm", vulnerabilities=[vuln])
    server = MCPServer(
        name="api-server", command="npx", packages=[pkg],
        env={"API_KEY": "***REDACTED***"},
    )
    agent = Agent(
        name="test-agent", agent_type=AgentType.CUSTOM,
        config_path="arn:aws:bedrock:us-east-1:123:agent/ABC",
        source="aws-bedrock", mcp_servers=[server],
    )
    report = AIBOMReport(agents=[agent])
    br = BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=["API_KEY"], exposed_tools=[], risk_score=7.5,
    )
    return report, [br]


def test_graph_elements_include_provider_nodes():
    """Cloud-sourced agents get a provider parent node."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii)
    provider_nodes = [e for e in elements if e.get("data", {}).get("type") == "provider"]
    assert len(provider_nodes) == 1
    assert provider_nodes[0]["data"]["id"] == "provider:aws-bedrock"


def test_graph_cve_nodes():
    """Blast radii produce CVE leaf nodes connected to packages."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii, include_cve_nodes=True)
    cve_nodes = [e for e in elements if "cve:" in e.get("data", {}).get("id", "")]
    assert len(cve_nodes) >= 1
    assert cve_nodes[0]["data"]["label"] == "CVE-2024-1234"
    affects_edges = [e for e in elements if e.get("data", {}).get("type") == "affects"]
    assert len(affects_edges) >= 1


def test_graph_no_cve_nodes_when_disabled():
    """CVE nodes can be excluded."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii, include_cve_nodes=False)
    cve_nodes = [e for e in elements if "cve:" in e.get("data", {}).get("id", "")]
    assert len(cve_nodes) == 0


def test_graph_json_format():
    """Graph output produces valid JSON with elements list."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii)
    result = json.dumps({"elements": elements, "format": "cytoscape"})
    parsed = json.loads(result)
    assert "elements" in parsed
    assert isinstance(parsed["elements"], list)
    assert parsed["format"] == "cytoscape"


# ─── CLI Cloud Flag Tests ────────────────────────────────────────────────────


def test_dry_run_lists_aws_apis():
    """--dry-run --aws mentions AWS APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--aws"])
    assert result.exit_code == 0
    assert "AWS" in result.output or "Bedrock" in result.output


def test_dry_run_lists_databricks_apis():
    """--dry-run --databricks mentions Databricks APIs."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--databricks"])
    assert result.exit_code == 0
    assert "Databricks" in result.output


def test_dry_run_lists_snowflake_apis():
    """--dry-run --snowflake mentions Snowflake APIs."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--snowflake"])
    assert result.exit_code == 0
    assert "Snowflake" in result.output


def test_graph_format_in_help():
    """--format graph is listed as a valid option."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "graph" in result.output


# ─── Snowflake Deep Discovery Tests ─────────────────────────────────────────


def test_snowflake_cortex_agents_discovered():
    """SHOW AGENTS returns Cortex Agent objects with correct source."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_cortex_agents

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.description = [("name",), ("database_name",), ("schema_name",), ("owner",), ("profile",)]
    mock_cursor.fetchall.return_value = [
        ("my-agent", "DB1", "PUBLIC", "ADMIN", '{"display_name": "My AI Agent"}'),
    ]

    agents, warnings = _discover_cortex_agents(mock_conn, "myorg")

    assert len(agents) == 1
    assert agents[0].source == "snowflake-cortex-agent"
    assert "My AI Agent" in agents[0].name


def test_snowflake_mcp_servers_discovered():
    """SHOW MCP SERVERS returns MCP server agents with source='snowflake-mcp'."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_mcp_servers

    mock_conn = MagicMock()
    # First cursor for SHOW MCP SERVERS
    show_cursor = MagicMock()
    show_cursor.description = [("name",), ("database_name",), ("schema_name",)]
    show_cursor.fetchall.return_value = [("my-mcp-server", "DB1", "PUBLIC")]

    # Second cursor for DESCRIBE MCP SERVER (returns empty — no YAML spec)
    describe_cursor = MagicMock()
    describe_cursor.description = [("property",), ("property_value",)]
    describe_cursor.fetchall.return_value = []

    mock_conn.cursor.side_effect = [show_cursor, describe_cursor]

    agents, warnings = _discover_mcp_servers(mock_conn, "myorg")

    assert len(agents) == 1
    assert agents[0].source == "snowflake-mcp"
    assert "my-mcp-server" in agents[0].name


def test_snowflake_query_history_parsing():
    """CREATE MCP SERVER/AGENT statements are parsed correctly."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _parse_create_statement_name

    assert _parse_create_statement_name("CREATE MCP SERVER my_server WITH SPEC...") == "my_server"
    assert _parse_create_statement_name("CREATE OR REPLACE MCP SERVER db.schema.srv1 ...") == "srv1"
    assert _parse_create_statement_name("CREATE AGENT IF NOT EXISTS my_agent ...") == "my_agent"
    assert _parse_create_statement_name('CREATE AGENT "MyAgent" ...') == "MyAgent"
    assert _parse_create_statement_name("SELECT 1") is None


def test_snowflake_custom_tools_discovered():
    """User-defined functions are discovered as MCPTool objects."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_custom_tools

    mock_conn = MagicMock()
    mock_cursor_funcs = MagicMock()
    mock_cursor_procs = MagicMock()

    mock_cursor_funcs.fetchall.return_value = [
        ("my_func", "(VARCHAR, NUMBER)", "TABLE", "PYTHON"),
    ]
    mock_cursor_procs.fetchall.return_value = [
        ("my_proc", "(VARCHAR)", "VARCHAR", "SQL"),
    ]

    mock_conn.cursor.side_effect = [mock_cursor_funcs, mock_cursor_procs]

    tools, warnings = _discover_custom_tools(mock_conn, "myorg")

    assert len(tools) == 2
    assert tools[0].name == "my_func"
    assert "PYTHON" in tools[0].description
    assert "external runtime" in tools[0].description
    assert tools[1].name == "my_proc"
    assert "external runtime" not in tools[1].description  # SQL is safe


def test_snowflake_system_execute_sql_flagged():
    """SYSTEM_EXECUTE_SQL tools get a HIGH-RISK flag in their description."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _describe_mcp_server_tools

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    yaml_spec = (
        "tools:\n"
        "  - name: run_query\n"
        "    type: SYSTEM_EXECUTE_SQL\n"
        "    description: Execute arbitrary SQL\n"
        "  - name: get_data\n"
        "    type: CUSTOM\n"
        "    description: Fetch data from table\n"
    )
    mock_cursor.description = [("property",), ("property_value",)]
    mock_cursor.fetchall.return_value = [("spec", yaml_spec)]

    tools = _describe_mcp_server_tools(mock_conn, "srv1", "DB1", "PUBLIC", [])

    assert len(tools) == 2
    sql_tool = [t for t in tools if t.name == "run_query"][0]
    assert "HIGH-RISK" in sql_tool.description
    assert "SYSTEM_EXECUTE_SQL" in sql_tool.description
    custom_tool = [t for t in tools if t.name == "get_data"][0]
    assert "HIGH-RISK" not in custom_tool.description


def test_snowflake_query_history_audit():
    """Query history produces audit agents from CREATE statements."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_from_query_history

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = [
        ("CREATE MCP SERVER my_server SPEC = '...'", "admin", "2025-01-01"),
        ("CREATE AGENT my_agent AS ...", "dev_user", "2025-01-02"),
    ]

    agents, warnings = _discover_from_query_history(mock_conn, "myorg")

    assert len(agents) == 2
    mcp_audit = [a for a in agents if a.source == "snowflake-mcp-audit"]
    agent_audit = [a for a in agents if a.source == "snowflake-agent-audit"]
    assert len(mcp_audit) == 1
    assert len(agent_audit) == 1


# ─── AWS Deep Discovery Tests ───────────────────────────────────────────────


def test_aws_lambda_direct_discovery():
    """Standalone Lambda functions are discovered when include_lambda=True."""
    _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"

    mock_bedrock = MagicMock()
    mock_bedrock_paginator = MagicMock()
    mock_bedrock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_bedrock.get_paginator.return_value = mock_bedrock_paginator

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}

    mock_lambda = MagicMock()
    mock_lambda_paginator = MagicMock()
    mock_lambda_paginator.paginate.return_value = [{
        "Functions": [
            {"FunctionName": "ai-inference", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:ai-inference",
             "Runtime": "python3.12"},
            {"FunctionName": "java-util", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:java-util",
             "Runtime": "java17"},
        ]
    }]
    mock_lambda.get_paginator.return_value = mock_lambda_paginator
    mock_lambda.get_function.return_value = {"Configuration": {"Runtime": "python3.12", "Layers": []}}

    mock_session.client.side_effect = lambda svc, **kw: {
        "bedrock-agent": mock_bedrock, "ecs": mock_ecs, "lambda": mock_lambda,
    }[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1", include_lambda=True)

    lambda_agents = [a for a in agents if a.source == "aws-lambda"]
    assert len(lambda_agents) == 1
    assert "ai-inference" in lambda_agents[0].name
    assert lambda_agents[0].version == "python3.12"


def test_aws_step_functions_parsing():
    """Step Functions definitions are parsed for Lambda/SageMaker ARNs."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _extract_sfn_task_resources

    definition = {
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:lambda:us-east-1:123:function:my-func",
            },
            "ParallelStep": {
                "Type": "Parallel",
                "Branches": [{"States": {
                    "Branch1": {
                        "Type": "Task",
                        "Resource": "arn:aws:sagemaker:us-east-1:123:endpoint/my-ep",
                    }
                }}],
            },
            "MapStep": {
                "Type": "Map",
                "Iterator": {"States": {
                    "MapTask": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:123:function:map-func",
                    }
                }},
            },
        }
    }

    arns = _extract_sfn_task_resources(definition)
    assert len(arns) == 3
    assert "arn:aws:lambda:us-east-1:123:function:my-func" in arns
    assert "arn:aws:sagemaker:us-east-1:123:endpoint/my-ep" in arns
    assert "arn:aws:lambda:us-east-1:123:function:map-func" in arns


def test_aws_ec2_requires_tag_filter():
    """EC2 discovery without tag filter returns a warning, not instances."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _discover_ec2_instances

    mock_session = MagicMock()
    agents, warnings = _discover_ec2_instances(mock_session, "us-east-1", {})

    assert len(agents) == 0
    assert any("tag" in w.lower() for w in warnings)


def test_aws_ec2_tag_discovery():
    """EC2 instances matching tags are discovered as agents."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _discover_ec2_instances

    mock_session = MagicMock()
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-12345",
                "InstanceType": "p4d.24xlarge",
                "ImageId": "ami-abc123",
                "Tags": [{"Key": "Name", "Value": "gpu-training"}],
            }]
        }]
    }]
    mock_ec2.get_paginator.return_value = mock_paginator

    agents, warnings = _discover_ec2_instances(mock_session, "us-east-1", {"Environment": "ai-prod"})

    assert len(agents) == 1
    assert agents[0].source == "aws-ec2"
    assert "gpu-training" in agents[0].name
    assert "p4d.24xlarge" in agents[0].version


def test_aws_eks_reuses_k8s():
    """EKS discovery calls k8s.discover_images() with the cluster as context."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))

    mock_session = MagicMock()
    mock_eks = MagicMock()
    mock_eks.list_clusters.return_value = {"clusters": ["my-eks-cluster"]}
    mock_session.client.return_value = mock_eks

    # Patch at the source (agent_bom.k8s) since _discover_eks_images imports lazily
    with patch("agent_bom.k8s.discover_images") as mock_discover:
        mock_discover.return_value = [("nginx:1.25", "web-pod", "nginx")]
        from agent_bom.cloud.aws import _discover_eks_images
        agents, warnings = _discover_eks_images(mock_session, "us-east-1")

    eks_agents = [a for a in agents if a.source == "aws-eks"]
    assert len(eks_agents) == 1
    assert "my-eks-cluster" in eks_agents[0].name
    mock_discover.assert_called_once_with(all_namespaces=True, context="my-eks-cluster")


# ─── Nebius Provider Tests ──────────────────────────────────────────────────


def _install_mock_nebius():
    """Install a mock nebius SDK in sys.modules."""
    nebius = types.ModuleType("nebius")
    nebius.Client = MagicMock
    sys.modules.setdefault("nebius", nebius)
    return nebius


def test_nebius_missing_sdk():
    """Helpful error when nebius is not installed."""
    with patch.dict(sys.modules, {"nebius": None}):
        import agent_bom.cloud.nebius as nb_mod
        try:
            importlib.reload(nb_mod)
        except Exception:
            pass
        with pytest.raises(CloudDiscoveryError, match="nebius is required"):
            from agent_bom.cloud.nebius import discover
            discover()


def test_nebius_k8s_clusters():
    """Nebius K8s clusters are discovered as agents."""
    _install_mock_nebius()
    importlib.reload(importlib.import_module("agent_bom.cloud.nebius"))
    from agent_bom.cloud.nebius import discover

    mock_client = MagicMock()
    mock_cluster = MagicMock()
    mock_cluster.id = "cluster-abc"
    mock_cluster.name = "gpu-cluster"
    mock_cluster.status = "RUNNING"
    mock_client.kubernetes.clusters.list.return_value = [mock_cluster]
    mock_client.containers = None  # No container service

    with patch("nebius.Client", return_value=mock_client):
        agents, warnings = discover(api_key="fake-key", project_id="proj-123")

    k8s_agents = [a for a in agents if a.source == "nebius-k8s"]
    assert len(k8s_agents) == 1
    assert "gpu-cluster" in k8s_agents[0].name


# ─── CLI Deep Flag Tests ────────────────────────────────────────────────────


def test_dry_run_lists_nebius_apis():
    """--dry-run --nebius mentions Nebius APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--nebius"])
    assert result.exit_code == 0
    assert "Nebius" in result.output


def test_dry_run_aws_lambda_flag():
    """--dry-run --aws --aws-include-lambda mentions Lambda ListFunctions."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--aws", "--aws-include-lambda"])
    assert result.exit_code == 0
    assert "Lambda" in result.output
    assert "ListFunctions" in result.output
