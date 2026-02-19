"use client";

import { useEffect, useState } from "react";
import { api, Agent } from "@/lib/api";
import { Server, Package, Wrench, Key, ShieldCheck, ShieldAlert } from "lucide-react";

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.listAgents()
      .then((r) => setAgents(r.agents))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
        <p className="text-zinc-400 text-sm mt-1">
          Auto-discovered local AI agent configurations
        </p>
      </div>

      {loading && <p className="text-zinc-500 text-sm">Discovering agents…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && agents.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Server className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No agents discovered locally.</p>
          <p className="text-zinc-600 text-xs mt-1">
            Install Claude Desktop, Cursor, or Windsurf and configure MCP servers.
          </p>
        </div>
      )}

      <div className="space-y-4">
        {agents.map((agent, i) => (
          <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="font-semibold text-zinc-100">{agent.name}</h2>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-xs font-mono text-zinc-500">{agent.agent_type}</span>
                  {agent.source && (
                    <span className="text-xs text-zinc-600">· {agent.source}</span>
                  )}
                </div>
              </div>
              <span className="text-xs font-mono bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-zinc-400">
                {agent.mcp_servers.length} server{agent.mcp_servers.length !== 1 ? "s" : ""}
              </span>
            </div>

            <div className="space-y-2">
              {agent.mcp_servers.map((srv, j) => (
                <div key={j} className="bg-zinc-800 border border-zinc-700 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold text-zinc-200">{srv.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {srv.transport && (
                        <span className="text-xs text-zinc-600 font-mono">{srv.transport}</span>
                      )}
                    </div>
                  </div>

                  {srv.command && (
                    <div className="text-xs font-mono text-zinc-500 mb-2">
                      $ {srv.command} {srv.env ? Object.keys(srv.env).length > 0 ? `[${Object.keys(srv.env).length} env vars]` : "" : ""}
                    </div>
                  )}

                  <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
                    {srv.packages.length > 0 && (
                      <span className="flex items-center gap-1">
                        <Package className="w-3 h-3" />
                        {srv.packages.length} package{srv.packages.length !== 1 ? "s" : ""}
                      </span>
                    )}
                    {srv.tools && srv.tools.length > 0 && (
                      <span className="flex items-center gap-1">
                        <Wrench className="w-3 h-3" />
                        {srv.tools.length} tool{srv.tools.length !== 1 ? "s" : ""}
                      </span>
                    )}
                    {srv.env && Object.keys(srv.env).length > 0 && (
                      <span className="flex items-center gap-1 text-orange-400">
                        <Key className="w-3 h-3" />
                        {Object.keys(srv.env).length} credential{Object.keys(srv.env).length !== 1 ? "s" : ""}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
