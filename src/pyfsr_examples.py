"""Build the "pyfsr" code-sample tab from pyfsr's own doctests.

Why this exists: a hand-copied sample (2026-07-13) imported a `Client` class
that doesn't exist in pyfsr (the real class is `FortiSOAR`) and used a
deprecated auth form. It looked plausible and wasn't. Extracting straight
from pyfsr's docstrings means the sample is provably real usage -- pyfsr's
own test suite runs these doctests in CI, so if pyfsr's tests are green, the
extracted sample is guaranteed to import and call real names correctly.

Two source kinds per (http_method, path) entry in `PYFSR_EXAMPLES`:

  ("doctest", "<module>[:Class.method]")
      Auto-extracted from a real `>>>` block in pyfsr via `doctest.DocTestParser`.
      Requires `pyfsr` importable (add it to this project's dependencies).

  ("manual", "<source>")
      Hand-written, for ops pyfsr doesn't have a doctest for yet. Every entry
      here MUST have a matching case in `tests/test_pyfsr_examples.py` that
      runs it against a mocked FortiSOAR session -- doctest-sourced samples
      get that proof for free from pyfsr's own CI; manual ones don't, so we
      have to earn it locally instead. Treat a manual entry as a standing
      TODO to add the doctest upstream in pyfsr and flip it to "doctest".

Called from `build_curated.py` to attach `x-codeSamples` to matching ops.
"""

from __future__ import annotations

import doctest
import importlib
import inspect
import re
import typing

_PREAMBLE = (
    "from pyfsr import FortiSOAR\n\n"
    "client = FortiSOAR(\n"
    "    base_url=\"https://fortisoar.example.com\",\n"
    "    username=\"<user>\",\n"
    "    password=\"<password>\",\n"
    ")\n\n"
)

# pyfsr's replay fixture used inside doctests -- not part of the public API,
# so it's stripped and replaced by the real construction above.
_DEMO_CLIENT_LINE_RE = re.compile(r"(?m)^client\s*=\s*demo_client\(\)\s*\n?")
# Some doctests open with `from pyfsr._testing import demo_client` before the
# `client = demo_client()` line. The import is also internal-only -- strip it
# so the rendered sample doesn't show a stray unused import.
_DEMO_IMPORT_RE = re.compile(r"(?m)^from\s+pyfsr\._testing\s+import\s+demo_client\s*\n?")
# Doctest directives (`# doctest: +SKIP`, `+ELLIPSIS`, ...) are pytest/doctest
# runner hints, not part of the code a reader would paste.
_DOCTEST_DIRECTIVE_RE = re.compile(r"[ \t]*#\s*doctest:\s*\+\w+\s*$", re.M)


def _resolve(dotted_path: str):
    """Import ``pkg.module`` or ``pkg.module:Class.method`` and return the object."""
    if ":" in dotted_path:
        mod_path, attr_path = dotted_path.split(":", 1)
    else:
        mod_path, attr_path = dotted_path, None
    obj = importlib.import_module(mod_path)
    if attr_path:
        for part in attr_path.split("."):
            obj = getattr(obj, part)
    return obj


def extract_doctest_examples(dotted_path: str) -> str:
    """Return cleaned, presentable source for every ``>>>`` example in ``dotted_path``'s docstring.

    Concatenates every example in the docstring (a doctest is often written as
    several `>>>` blocks building on each other), strips the `demo_client()`
    fixture line and doctest directive comments, and -- for a trailing bare
    expression that doctest checks via its printed repr (e.g.
    ``(alert.name, ...)`` asserted against a literal) -- wraps it in ``print()``
    so the sample actually shows something when run, instead of silently
    evaluating and discarding the result the way a real doctest does.
    """
    obj = _resolve(dotted_path)
    doc = obj.__doc__ or ""
    examples = doctest.DocTestParser().get_examples(doc)
    if not examples:
        raise ValueError(f"No doctest examples found in {dotted_path!r}")

    lines = []
    for ex in examples:
        src = ex.source.rstrip("\n")
        src = _DOCTEST_DIRECTIVE_RE.sub("", src)
        if ex.want and "=" not in src.splitlines()[0].split("(")[0]:
            # Bare expression whose repr doctest checked -- show it for real.
            # Strip inline comments first: a ``#`` comment with a ``)`` would
            # unbalance the ``print(...)`` wrapper (e.g.
            # ``x[0].title  # schema (step: foo)`` -> ``print(x[0].title)``).
            first_line = src.splitlines()[0]
            comment_at = first_line.find("  #")
            if comment_at != -1:
                code = first_line[:comment_at].rstrip()
                rest = "\n".join(src.splitlines()[1:])
                src = f"print({code})" + (f"\n{rest}" if rest else "")
            else:
                src = f"print({src})"
        lines.append(src)

    body = "\n".join(lines)
    body = _DEMO_CLIENT_LINE_RE.sub("", body)
    body = _DEMO_IMPORT_RE.sub("", body)
    return _PREAMBLE + body.strip("\n")


def manual_example(body: str) -> str:
    """Hand-written fallback source for an op without a pyfsr doctest yet."""
    return _PREAMBLE + body


# (http_method, path) -> ("doctest", dotted-path) | ("manual", source-body)
#
# Keep "manual" entries to the minimum needed to cover an op with no pyfsr
# doctest; prefer adding the doctest upstream in pyfsr and switching to
# "doctest" over growing this list.
#
# Generic template entries (e.g. ``/api/3/{collection}``) also serve as the
# fallback for concrete collection paths (``/api/3/alerts``, ``/api/3/agents``)
# via ``_generic_fallback`` in ``apply_pyfsr_samples`` — no per-module entry
# needed unless a typed wrapper in ``pyfsr.api.<module>`` has a richer
# doctest for that specific path.
PYFSR_EXAMPLES: dict[tuple[str, str], tuple[str, str]] = {
    # Generic record CRUD (pyfsr.records) — covers every concrete collection
    # path via fallback (alerts, incidents, tasks, comments, agents, ...).
    ("get", "/api/3/{collection}"): ("doctest", "pyfsr.records:RecordSet.list"),
    ("get", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records"),
    ("post", "/api/3/{collection}"): ("doctest", "pyfsr.records:RecordSet.create"),
    ("put", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records:RecordSet.update"),
    ("delete", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records:RecordSet.delete"),
    # Generic record bulk ops (pyfsr.records)
    ("get", "/api/3/{module}/{recordId}/comments"): ("doctest", "pyfsr.records:RecordSet.comments"),
    ("post", "/api/3/upsert/{moduleType}"): ("doctest", "pyfsr.records:RecordSet.upsert"),
    ("post", "/api/3/bulkupsert/{moduleType}"): ("doctest", "pyfsr.records:RecordSet.bulk_upsert"),
    ("post", "/api/3/insert/{moduleType}"): ("doctest", "pyfsr.records:RecordSet.bulk_insert"),
    # Scheduled tasks (Tier 1a)
    ("post", "/api/wf/api/scheduled/"): ("doctest", "pyfsr.api.schedules:SchedulesAPI.create"),
    ("delete", "/api/wf/api/scheduled/{id}/"): ("doctest", "pyfsr.api.schedules:SchedulesAPI.delete"),
    ("post", "/api/wf/api/scheduled/trigger-now/"): ("doctest", "pyfsr.api.schedules:SchedulesAPI.trigger_now"),
    # Notifications (Tier 1c)
    ("post", "/api/rule/api/system-notification/notifications/"): ("doctest", "pyfsr.api.notifications:NotificationsAPI.list"),
    ("post", "/api/rule/api/system-notification/purge/"): ("doctest", "pyfsr.api.notifications:NotificationsAPI.purge"),
    # ------------------------------------------------------------------
    # Typed wrappers — one per (method, path). These take precedence over
    # the generic RecordSet fallback above for their specific path, so a
    # reader sees the typed surface (client.alerts.get(...)) rather than
    # the generic one (client.records("alerts").get(...)) where both exist.
    # Alerts
    ("get", "/api/3/alerts/{uuid}"): ("doctest", "pyfsr.api.alerts:AlertsAPI"),
    # Comments / Routers / Roles / Teams (typed list)
    ("get", "/api/3/comments"): ("doctest", "pyfsr.api.comments:CommentsAPI.list"),
    ("get", "/api/3/routers"): ("doctest", "pyfsr.api.routers:RoutersAPI.list"),
    ("get", "/api/3/roles"): ("doctest", "pyfsr.api.roles:RolesAPI.list"),
    ("get", "/api/3/teams"): ("doctest", "pyfsr.api.teams:TeamsAPI.list"),
    # Agents (lifecycle + installer + connector push)
    ("get", "/api/3/agents"): ("doctest", "pyfsr.api.agents:AgentsAPI.list"),
    ("get", "/api/3/agents/{uuid}"): ("doctest", "pyfsr.api.agents:AgentsAPI.get"),
    ("post", "/api/3/agents"): ("doctest", "pyfsr.api.agents:AgentsAPI.create"),
    ("delete", "/api/3/agents/{uuid}"): ("doctest", "pyfsr.api.agents:AgentsAPI.delete"),
    ("post", "/api/integration/agent-installer/"): ("doctest", "pyfsr.api.agents:AgentsAPI.installer"),
    ("post", "/api/integration/install-connector/"): ("doctest", "pyfsr.api.agents:AgentsAPI.install_connector"),
    ("put", "/api/integration/install-connector/"): ("doctest", "pyfsr.api.agents:AgentsAPI.upgrade_connector"),
    ("delete", "/api/integration/install-connector/"): ("doctest", "pyfsr.api.agents:AgentsAPI.uninstall_connector"),
    ("get", "/api/integration/agent-heartbeat/{agent}/"): ("doctest", "pyfsr.api.agents:AgentsAPI.heartbeat"),
    # API keys
    ("get", "/api/3/api_keys"): ("doctest", "pyfsr.api.api_keys:ApiKeysAPI.list"),
    ("get", "/api/3/api_keys/{uuid}"): ("doctest", "pyfsr.api.api_keys:ApiKeysAPI.get"),
    ("post", "/api/3/api_keys"): ("doctest", "pyfsr.api.api_keys:ApiKeysAPI.create"),
    ("put", "/api/3/api_keys/{uuid}"): ("doctest", "pyfsr.api.api_keys:ApiKeysAPI.update"),
    # System queries / model metadatas
    ("get", "/api/3/model_metadatas"): ("doctest", "pyfsr.api.system_queries:SystemQueriesAPI.model_iri"),
    # Solution packs / import jobs
    ("post", "/api/3/solutionpacks/install"): ("doctest", "pyfsr.api.solution_packs:SolutionPackAPI.install"),
    ("post", "/api/3/import_jobs"): ("doctest", "pyfsr.api.import_config:ImportConfigAPI.create_job"),
    # System (version / permissions / feature-access)
    ("get", "/api/version"): ("doctest", "pyfsr.api.system:SystemAPI.version"),
    ("get", "/api/permissions/current"): ("doctest", "pyfsr.api.system:SystemAPI.permissions"),
    ("get", "/api/product/feature-access"): ("doctest", "pyfsr.api.system:SystemAPI.feature_access"),
    # Search
    ("post", "/api/search"): ("doctest", "pyfsr.api.search:SearchAPI.search"),
    ("post", "/api/query/{collection}/{queryId}"): ("doctest", "pyfsr.api.search:SearchAPI.run_persisted"),
    # Feeds (trigger-bypassing bulk ingest)
    ("post", "/api/ingest-feeds/indicators"): ("doctest", "pyfsr.api.feeds:IngestFeedsAPI.indicators"),
    ("post", "/api/ingest-feeds/observables"): ("doctest", "pyfsr.api.feeds:IngestFeedsAPI.observables"),
    ("post", "/api/ingest-feeds/reputation"): ("doctest", "pyfsr.api.feeds:IngestFeedsAPI.reputation"),
    ("post", "/api/ingest-feeds/threatintel"): ("doctest", "pyfsr.api.feeds:IngestFeedsAPI.threatintel"),
    ("post", "/api/ingest-feeds/stix-bundle"): ("doctest", "pyfsr.api.feeds:IngestFeedsAPI.stix_bundle"),
    # TAXII 2.1
    ("get", "/api/taxii/1/"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.discovery"),
    ("get", "/api/taxii/1/collections"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.collections"),
    ("get", "/api/taxii/1/collections/{uuid}"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.collection"),
    ("get", "/api/taxii/1/collections/{uuid}/manifest"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.manifest"),
    ("get", "/api/taxii/1/collections/{uuid}/objects"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.objects"),
    ("get", "/api/taxii/1/collections/{uuid}/objects/{stixId}"): ("doctest", "pyfsr.api.taxii:TaxiiAPI.object"),
    # Audit
    ("post", "/api/gateway/audit/activities"): ("doctest", "pyfsr.api.audit:AuditAPI.activities"),
    ("post", "/api/gateway/audit/activities/count"): ("doctest", "pyfsr.api.audit:AuditAPI.count"),
    ("get", "/api/gateway/audit/activities/{auditId}"): ("doctest", "pyfsr.api.audit:AuditAPI.get"),
    ("get", "/api/gateway/audit/operations"): ("doctest", "pyfsr.api.audit:AuditAPI.operations"),
    ("delete", "/api/gateway/audit/activities/ttl"): ("doctest", "pyfsr.api.audit:AuditAPI.disable_ttl"),
    # Connectors (execute)
    ("post", "/api/integration/execute/"): ("doctest", "pyfsr.api.connectors:ConnectorsAPI.execute"),
    # Playbooks
    ("get", "/api/wf/api/workflows/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.execution_history"),
    ("get", "/api/wf/api/historical-workflows/{pk}/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.get_execution"),
    ("post", "/api/wf/api/workflows/{pk}/start/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.start"),
    ("post", "/api/wf/api/workflows/{pk}/retry/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.retry"),
    ("get", "/api/wf/api/workflows/count/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.count"),
    ("post", "/api/wf/api/workflows/log_list/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.log_list"),
    ("post", "/api/wf/api/query/workflow_logs/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.query_logs"),
    ("post", "/api/wf/api/jinja-editor/"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.render_jinja"),
    ("post", "/api/triggers/1/{name}"): ("doctest", "pyfsr.api.playbooks:PlaybooksAPI.trigger_by_name"),
    # Manual input
    ("post", "/api/wf/api/manual-wf-input/list_wfinput/"): ("doctest", "pyfsr.api.manual_input:ManualInputAPI.list"),
    ("post", "/api/wf/api/manual-wf-input/{pk}/retrieve_wfinput/"): ("doctest", "pyfsr.api.manual_input:ManualInputAPI.retrieve"),
    ("post", "/api/wf/api/workflows/{pk}/wfinput_resume/"): ("doctest", "pyfsr.api.manual_input:ManualInputAPI.resume"),
}


def build_pyfsr_sample(http_method: str, path: str) -> dict:
    """Return the Scalar ``x-codeSamples`` entry for ``(http_method, path)``.

    Raises ``KeyError`` if there's no entry -- callers should only call this
    for paths they've deliberately added to ``PYFSR_EXAMPLES``.
    """
    kind, payload = PYFSR_EXAMPLES[(http_method, path)]
    source = extract_doctest_examples(payload) if kind == "doctest" else manual_example(payload)
    return {"lang": "python", "label": "pyfsr", "source": source}


_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}

# Concrete FortiSOAR record collections the spec defines as their own paths
# (e.g. ``/api/3/alerts``) separate from the generic ``/api/3/{collection}``
# template. When a concrete path has no specific ``PYFSR_EXAMPLES`` entry,
# ``_generic_fallback`` maps it back to the template so it inherits the
# generic ``RecordSet`` doctest rather than rendering with no sample.
_KNOWN_COLLECTIONS = {
    "alerts", "incidents", "tasks", "comments", "agents", "routers",
    "picklists", "picklist_names", "model_metadatas", "files", "roles",
    "teams", "api_keys", "user_queries", "widgets", "export_templates",
    "import_jobs", "export_jobs",
}


def _generic_fallback(http_method: str, path: str) -> tuple[str, str] | None:
    """Map a concrete ``/api/3/<collection>[/<id>]`` path to its generic template key.

    Returns the ``(method, template_path)`` key to look up in ``PYFSR_EXAMPLES``,
    or ``None`` if ``path`` isn't a concrete collection path we recognize.
    Only matches known collection names so non-collection paths like
    ``/api/3/solutionpacks/install`` are left alone.
    """
    parts = path.strip("/").split("/")
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "3":
        return None
    if parts[2] not in _KNOWN_COLLECTIONS:
        return None
    if len(parts) == 3:
        return (http_method, "/api/3/{collection}")
    if len(parts) == 4:
        return (http_method, "/api/3/{collection}/{uuid}")
    return None


def apply_pyfsr_samples(paths: dict) -> int:
    """Attach ``x-codeSamples`` to every op in ``paths`` (keyed by path -> {method: op})
    that has a ``PYFSR_EXAMPLES`` entry.

    A concrete collection path (e.g. ``/api/3/alerts``) with no specific entry
    falls back to its generic template (``/api/3/{collection}``) so it inherits
    the generic ``RecordSet`` doctest. Returns the count applied. Raises if
    extraction fails for any mapped entry -- a broken sample should fail the
    build, not ship silently broken.
    """
    applied = 0
    for path, path_item in paths.items():
        for http_method, op in path_item.items():
            if http_method not in _HTTP_METHODS:
                continue
            key = (http_method, path)
            if key not in PYFSR_EXAMPLES:
                fallback = _generic_fallback(http_method, path)
                if fallback is None or fallback not in PYFSR_EXAMPLES:
                    continue
                key = fallback
            op["x-codeSamples"] = [build_pyfsr_sample(*key)]
            applied += 1
    return applied


# ---------------------------------------------------------------------------
# Response-model mapping (Phase 3)
#
# Each (http_method, path) wired in ``PYFSR_EXAMPLES`` points at a pyfsr
# method whose return type annotation names the Pydantic class pyfsr parses
# the response into. Surfacing that class on the op's 2xx response (as
# ``x-pyfsr-response-model``) tells a reader what typed object they get back
# from the pyfsr sample, in parallel with the request-side ``x-codeSamples``.

# Annotation tokens that mean "no typed model worth surfacing" -- skip these.
_SKIP_ANN = {
    "dict", "list", "bytes", "str", "int", "float", "bool",
    "NoneType", "None", "Any", "_empty", "HydraPage",
}


def _ann_to_model(ann: object) -> str | None:
    """Reduce a return annotation to a short pyfsr model name, or ``None``.

    Walks typing constructs (``Union``/``X | Y``, ``list[...]``) and returns
    only the typed-model side: ``list[Agent]`` -> ``"list[Agent]"``,
    ``ManualInput | dict[str, Any]`` -> ``"ManualInput"``,
    ``dict[str, Any]`` -> ``None``. Also handles PEP-563 string annotations
    (pyfsr uses ``from __future__ import annotations``).
    """
    if ann is inspect.Signature.empty:
        return None
    # PEP-563 string annotation -- try to eval it against the module globals
    if isinstance(ann, str):
        try:
            ann = eval(ann, vars(typing))  # noqa: S307 - annotation string from source
        except Exception:
            # Can't resolve -- fall through to the string-based path below.
            s = ann.split(".")[-1] if "." in ann else ann
            return None if s in _SKIP_ANN or s.startswith("dict[") else s
    origin = typing.get_origin(ann)
    args = typing.get_args(ann)
    # Union (includes PEP 604 ``X | Y`` as types.UnionType on 3.10+)
    if origin is typing.Union or origin is getattr(__import__("types"), "UnionType", object()):
        parts = [_ann_to_model(a) for a in args]
        parts = [p for p in parts if p]
        return " | ".join(dict.fromkeys(parts)) if parts else None
    if origin is list:
        inner = _ann_to_model(args[0]) if args else None
        return f"list[{inner}]" if inner else None
    # Bare class -- prefer ``__name__``; fall back to the last segment of a
    # qualified path (e.g. ``pyfsr.models._system.SolutionPackInstallResponse``).
    name = getattr(ann, "__name__", None)
    if name is None:
        s = str(ann)
        name = s.split(".")[-1] if "." in s else s
    if name in _SKIP_ANN:
        return None
    return name


def response_model_for(http_method: str, path: str) -> str | None:
    """Return the pyfsr response model class name for ``(http_method, path)``, or ``None``.

    Resolves the doctest target method (with the generic-template fallback)
    and reads its return type annotation. Returns a short string like
    ``"Alert"`` / ``"list[Agent]"`` / ``"SolutionPackInstallResponse | InstallJobStatus"``,
    or ``None`` when the return type is ``dict``/``bytes``/``Any``/``None``
    (no typed model worth surfacing).
    """
    key = (http_method, path)
    if key not in PYFSR_EXAMPLES:
        fallback = _generic_fallback(http_method, path)
        if fallback is None or fallback not in PYFSR_EXAMPLES:
            return None
        key = fallback
    kind, payload = PYFSR_EXAMPLES[key]
    if kind != "doctest":
        return None
    try:
        obj = _resolve(payload)
        # ``typing.get_type_hints`` resolves PEP-563 string annotations (pyfsr
        # uses ``from __future__ import annotations``) that ``inspect.signature``
        # would return verbatim. Fall back to the raw annotation on failure.
        try:
            hints = typing.get_type_hints(obj)
            ann = hints.get("return", inspect.Signature.empty)
        except Exception:
            ann = inspect.signature(obj).return_annotation
    except Exception:
        return None
    return _ann_to_model(ann)


def apply_pyfsr_response_models(paths: dict) -> int:
    """Attach ``x-pyfsr-response-model`` to each op's first 2xx response.

    The extension names the pyfsr Pydantic class that ``x-codeSamples`` would
    parse the response into, so readers see what typed object they get back.
    Skips ops with no pyfsr entry, no doctest (manual samples), or an
    untyped return (``dict[str, Any]`` / ``bytes`` / ``None`` / ``Any``).
    Returns the count attached.
    """
    applied = 0
    for path, path_item in paths.items():
        for http_method, op in path_item.items():
            if http_method not in _HTTP_METHODS:
                continue
            model = response_model_for(http_method, path)
            if not model:
                continue
            responses = op.get("responses") or {}
            # Attach to the first 2xx response we find (200, 201, 202, 204).
            for code, resp in responses.items():
                if str(code) in {"200", "201", "202", "204"}:
                    resp["x-pyfsr-response-model"] = model
                    applied += 1
                    break
    return applied
