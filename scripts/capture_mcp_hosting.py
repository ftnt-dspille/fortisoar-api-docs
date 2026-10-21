"""One-off capture: MCP hosting lifecycle + config import round-trip.

Companion to the ``ai`` scenario, which owns the read-side MCP captures
(JSON-RPC gateway, validate). This script captures the WRITE-side ops that
cannot run in a recurring scenario:

- ``POST /mcp/add/tools`` hosts a connector as an MCP server. The hosting
  registry keys on the config NAME and has NO API unhost: the name survives
  ``DELETE /api/3/mcp_configurations/{uuid}`` and keeps answering
  ``initialize`` under ``/mcp/connector/<name>/`` (with zero tools after the
  tools/delete call). One inert ghost name per execution of this script --
  do not loop it. Harmless because the ghost is not in the fsr-ai MCP config
  list agents consult, the config we host is ``active: false``, and the
  hosted operation does not exist on the target connector.
- ``POST /mcp/config/import`` replays the tool catalog we just exported for
  our own config (round-trip, no net change).
- ``DELETE /mcp/tools/delete`` records the live 204; on 8.0.0 the delete is
  a no-op for every body shape tried (tool name / tool uuid / server name
  as string items) -- the catalog entry survives. pyfsr's documented
  ``[{"uuid": .., "name": ..}]`` body does not match the wire (list[str]).

Safety / own-things contract: everything operates on an MCP configuration
this script creates (``live-`` name, ``type: connector``, ``active: false``
so no agent ever sees it), on a tool whose operation name does not exist on
the target connector (invocation would fail), and the config row is deleted
at the end (204).

Run: .venv/bin/python scripts/capture_mcp_hosting.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import live_test as lt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    s = lt.open_session(os.environ.get("FSR_API_KEY", ""))
    s.set_auth("jwt" if "jwt" in s.auth_modes else next(iter(s.auth_modes)))
    stamp = int(time.time())
    host_name = f"{lt.LIVE_PREFIX}mcp-host-{stamp}"
    tool_name = f"{lt.LIVE_PREFIX}noop-{stamp}"

    print(f"== hosting lifecycle for {host_name!r}")
    _, cfg = s.call("POST", "/api/3/mcp_configurations", want=(200, 201, 400, 401, 403),
                    json={"name": host_name, "url": "https://localhost/mcp/connector/aws/",
                          "transport": "http", "authentication": {"type": "FSR"},
                          "active": False, "type": "connector",
                          "description": "live-test own mcp hosting",
                          "metadata": {"connectorName": "aws", "requireConfiguration": False}})
    ou = (cfg or {}).get("uuid") if isinstance(cfg, dict) else None
    if not ou:
        print("config create failed; aborting (nothing to clean)")
        return 1

    try:
        _, hosted = s.call("POST", "/mcp/add/tools", want=(200, 201, 401, 403, 422, 500),
                           json={"mcp_configuration": {"name": host_name, "uuid": ou},
                                 "config": {},
                                 "metadata": {"name": host_name, "label": host_name,
                                              "version": "1.0.0", "connectorName": "aws"},
                                 "tools": [{"operation": tool_name, "title": f"live test {tool_name}",
                                            "description": "live-test tool entry", "category": None,
                                            "visible": True, "enabled": True, "parameters": [],
                                            "addTool": True}]})
        if hosted is None:
            print("add/tools did not return a body; continuing with catalog reads")

        _, catalog = s.call("POST", "/mcp/config/export", want=(200, 401, 403, 422, 500),
                            json=[{"uuid": ou}])
        # round-trip: import exactly what we exported for our own config
        if catalog:
            s.call("POST", "/mcp/config/import", want=(200, 201, 400, 401, 403, 422, 500),
                   json=catalog)

        put_body = {"uuid": ou,
                    "metadata": {"name": host_name, "connectorName": "aws",
                                 "label": host_name, "version": "1.0.0"},
                    "config": {}, "tools": [], "remove_tools": []}
        # the spec carries this route twice (``{mcp_config_uuid}`` from one
        # doc source, ``{uuid}`` from another) -- same wire route, capture both
        s.call("PUT", "/mcp/tools/{mcp_config_uuid}", want=(200, 204, 401, 403, 422, 500),
               path_params={"mcp_config_uuid": ou}, json=put_body)
        s.call("PUT", "/mcp/tools/{uuid}", want=(200, 204, 401, 403, 422, 500),
               path_params={"uuid": ou}, json=dict(put_body))

        tool_uuid = None
        for entry in catalog if isinstance(catalog, list) else []:
            for t in entry.get("tools") or []:
                if t.get("name") == tool_name:
                    tool_uuid = t.get("uuid")
        if tool_uuid:
            # recorded live: 204 but the catalog entry survives (no-op on 8.0.0)
            s.call("DELETE", "/mcp/tools/delete", want=(200, 204, 400, 401, 403, 422),
                   json=[tool_uuid])
    finally:
        s.call("DELETE", "/api/3/mcp_configurations/{uuid}", want=(200, 204, 401, 403, 404),
               path_params={"uuid": ou})

    lt.save_observations(s)
    print("done. NOTE: one inert ghost hosting name remains "
          f"({host_name!r}); see the module docstring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
