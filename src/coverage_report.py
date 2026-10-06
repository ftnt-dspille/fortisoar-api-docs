"""Cross-reference spec ops, pyfsr API methods, and PYFSR_EXAMPLES samples.

Surfaces three kinds of gaps:

  1. **spec_no_pyfsr** - spec ops that have no pyfsr code sample (the docs
     document an endpoint pyfsr doesn't cover yet).
  2. **pyfsr_no_spec** - pyfsr API methods that hit endpoints the spec doesn't
     document (pyfsr is ahead of the docs).
  3. **stale_samples** - PYFSR_EXAMPLES entries that don't match any spec op
     (the sample targets an endpoint the spec no longer carries, or a path
     template that was renamed).

Usage:
    python src/coverage_report.py
    python src/coverage_report.py --quiet          # counts only
    python src/coverage_report.py --section spec_no_pyfsr
"""
from __future__ import annotations

import argparse
import ast
import inspect
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "build" / "fortisoar.curated.openapi.yaml"

VERBS = ("get", "post", "put", "delete", "patch")


# ---------------------------------------------------------------------------
# 1. Spec ops - every (method, path) in the curated OpenAPI document.
# ---------------------------------------------------------------------------

def load_spec_ops() -> dict[str, dict]:
    """Return ``{f"{METHOD} {path}": op_dict}`` for every HTTP op in the spec."""
    spec = yaml.safe_load(SPEC_PATH.read_text())
    ops: dict[str, dict] = {}
    for path, methods in spec.get("paths", {}).items():
        for verb, op in methods.items():
            if verb in VERBS:
                ops[f"{verb.upper()} {path}"] = op
    return ops


# ---------------------------------------------------------------------------
# 2. pyfsr API methods → HTTP endpoint templates.
# ---------------------------------------------------------------------------

def _resolve_fstring(node: ast.JoinedStr, consts: dict[str, str],
                     params: set[str], self_attrs: dict[str, str] | None = None) -> str:
    """Reconstruct an f-string into an OpenAPI-style path template."""
    self_attrs = self_attrs or {}
    parts: list[str] = []
    for v in node.values:
        if isinstance(v, ast.Constant):
            parts.append(str(v.value))
        elif isinstance(v, ast.FormattedValue):
            inner = v.value
            if isinstance(inner, ast.Name):
                if inner.id in consts:
                    parts.append(str(consts[inner.id]))
                elif inner.id in params:
                    parts.append("{" + inner.id + "}")
                else:
                    parts.append("{" + inner.id + "}")
            elif isinstance(inner, ast.Attribute):
                # self.<attr> - resolve from __init__ assignments (e.g.
                # self.module = "alerts" → "alerts").
                if (isinstance(inner.value, ast.Name)
                        and inner.value.id == "self"
                        and inner.attr in self_attrs):
                    parts.append(self_attrs[inner.attr])
                else:
                    parts.append("{?}")
            else:
                parts.append("{?}")
    return "".join(parts)


def _extract_endpoints(cls: type, consts: dict[str, str]) -> list[tuple[str, str, str]]:
    """Return ``[(http_method, endpoint_template, method_name)]`` for one API class."""
    results: list[tuple[str, str, str]] = []
    # Merge module-level consts with class-level consts (e.g. ``_BASE = "/api/3/alerts"``
    # defined on the class, not the module).
    all_consts = dict(consts)
    for attr in dir(cls):
        if attr.startswith("_"):
            val = getattr(cls, attr, None)
            if isinstance(val, str):
                all_consts[attr] = val
    # Extract ``self.<attr> = "<value>"`` assignments from __init__ so we can
    # resolve f-strings like ``f"/api/3/{self.module}/{uuid}"``.
    self_attrs: dict[str, str] = {}
    init_method = getattr(cls, "__init__", None)
    if init_method:
        try:
            init_src = textwrap.dedent(inspect.getsource(init_method))
            init_tree = ast.parse(init_src)
            for node in ast.walk(init_tree):
                if (isinstance(node, ast.Assign)
                        and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Attribute)
                        and isinstance(node.targets[0].value, ast.Name)
                        and node.targets[0].value.id == "self"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    self_attrs[node.targets[0].attr] = node.value.value
        except (OSError, TypeError, SyntaxError):
            pass
    for m_name in sorted(dir(cls)):
        if m_name.startswith("_"):
            continue
        method = getattr(cls, m_name, None)
        if not callable(method):
            continue
        try:
            src = inspect.getsource(method)
        except (OSError, TypeError):
            continue
        src = textwrap.dedent(src)
        # Collect parameter names so we can resolve f-string interpolations.
        try:
            sig = inspect.signature(method)
            params = set(sig.parameters)
        except (ValueError, TypeError):
            params = set()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Attribute)
                    and isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "self"
                    and func.value.attr == "client"
                    and func.attr in ("get", "post", "put", "delete", "request")):
                continue
            http_method = func.attr.upper()
            if http_method == "REQUEST":
                # self.client.request("GET", endpoint, ...) - first positional
                # arg is the HTTP method string, second is the endpoint.
                if len(node.args) >= 2:
                    method_arg = node.args[0]
                    endpoint_arg = node.args[1]
                    if isinstance(method_arg, ast.Constant):
                        http_method = str(method_arg.value).upper()
                else:
                    continue
            else:
                if not node.args:
                    continue
                endpoint_arg = node.args[0]
            # Resolve the endpoint argument.
            if isinstance(endpoint_arg, ast.Constant) and isinstance(endpoint_arg.value, str):
                endpoint = endpoint_arg.value
            elif isinstance(endpoint_arg, ast.JoinedStr):
                endpoint = _resolve_fstring(endpoint_arg, all_consts, params, self_attrs)
            else:
                continue
            # Strip query strings - we only care about the path template.
            endpoint = endpoint.split("?")[0]
            # Skip empty, unresolved, or broken endpoints.
            if not endpoint or endpoint == "{?}":
                continue
            # Skip endpoints that start with "{" (unresolved variable prefix)
            # or contain "{?" (partial resolution).
            if endpoint.startswith("{") and not endpoint.startswith("/{"):
                continue
            if "{?" in endpoint:
                continue
            results.append((http_method, endpoint, m_name))
    return results


def load_pyfsr_endpoints() -> dict[str, list[str]]:
    """Return ``{f"{METHOD} {path}": ["module.Class.method", ...]}``.

    Walks every ``pyfsr.api.*`` module, finds ``*API`` classes, and extracts
    the HTTP endpoint each public method calls.
    """
    import pyfsr.api as api_pkg
    import importlib

    registry: dict[str, list[str]] = {}
    # Walk the package directory to find all submodules (dir() only returns
    # already-imported names, which misses lazy submodules).
    pkg_dir = Path(api_pkg.__file__).parent
    for mod_file in sorted(pkg_dir.glob("*.py")):
        mod_name = mod_file.stem
        if mod_name.startswith("_"):
            continue
        full_name = f"pyfsr.api.{mod_name}"
        try:
            mod = importlib.import_module(full_name)
        except ImportError:
            continue
        # Collect module-level string constants.
        consts: dict[str, str] = {}
        try:
            mod_src = inspect.getsource(mod)
            mod_tree = ast.parse(mod_src)
            for node in ast.iter_child_nodes(mod_tree):
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            try:
                                consts[t.id] = ast.literal_eval(node.value)
                            except (ValueError, TypeError):
                                pass
        except (OSError, TypeError, SyntaxError):
            pass
        for cls_name in sorted(dir(mod)):
            if cls_name.startswith("_"):
                continue
            cls = getattr(mod, cls_name)
            if not (inspect.isclass(cls) and cls_name.endswith("API")):
                continue
            for http_m, endpoint, m_name in _extract_endpoints(cls, consts):
                key = f"{http_m} {endpoint}"
                registry.setdefault(key, []).append(f"{mod_name}.{cls_name}.{m_name}")
    return registry


# ---------------------------------------------------------------------------
# 3. PYFSR_EXAMPLES - the curated sample registry.
# ---------------------------------------------------------------------------

def load_pyfsr_samples() -> set[str]:
    """Return the set of ``f"{METHOD} {path}"`` keys in PYFSR_EXAMPLES."""
    sys.path.insert(0, str(ROOT / "src"))
    from pyfsr_examples import PYFSR_EXAMPLES, _generic_fallback, _KNOWN_COLLECTIONS

    sample_keys: set[str] = set()
    for (http_method, path) in PYFSR_EXAMPLES:
        sample_keys.add(f"{http_method.upper()} {path}")
    return sample_keys, PYFSR_EXAMPLES, _generic_fallback, _KNOWN_COLLECTIONS


# ---------------------------------------------------------------------------
# 4. Path-template normalization for matching.
# ---------------------------------------------------------------------------

def _normalize_path(path: str) -> str:
    """Normalize a path for cross-referencing.

    - Strip trailing slashes.
    - Collapse ``/api/ai/`` → ``/ai/`` (the spec uses ``/ai/`` for all AI paths;
      pyfsr uses ``/api/ai/`` - both prefixes work on the live appliance).
    """
    path = path.rstrip("/")
    if path.startswith("/api/ai/"):
        path = path[len("/api"):]
    return path


def _template_shape(path: str) -> str:
    """Reduce a path to its structural shape, ignoring parameter names.

    ``/api/3/alerts/{uuid}``  →  ``/api/3/alerts/{}```
    ``/api/3/alerts/{alert_id}``  →  ``/api/3/alerts/{}```
    """
    return re.sub(r"\{[^}]+\}", "{}", path)


def _match_concrete_to_template(concrete: str, templates: set[str]) -> str | None:
    """Match a concrete pyfsr endpoint against spec path templates.

    ``/api/3/agents/abc-123`` matches ``/api/3/agents/{uuid}``.
    """
    concrete_parts = concrete.strip("/").split("/")
    best: str | None = None
    for tmpl in templates:
        tmpl_parts = tmpl.strip("/").split("/")
        if len(tmpl_parts) != len(concrete_parts):
            continue
        ok = True
        for tp, cp in zip(tmpl_parts, concrete_parts):
            if tp.startswith("{") and tp.endswith("}"):
                continue
            if tp != cp:
                ok = False
                break
        if ok:
            return tmpl
    return best


def _match_template_to_template(pyfsr_path: str, spec_paths: set[str]) -> str | None:
    """Match two path templates that differ only in parameter names.

    ``/api/3/alerts/{alert_id}`` matches ``/api/3/alerts/{uuid}``.
    Also matches when the spec has a wildcard segment where pyfsr has a literal:
    ``/api/3/roles/{uuid}`` matches ``/api/3/{collection}/{uuid}``.
    """
    pyfsr_parts = pyfsr_path.strip("/").split("/")
    for sp in spec_paths:
        sp_parts = sp.strip("/").split("/")
        if len(sp_parts) != len(pyfsr_parts):
            continue
        ok = True
        for tp, cp in zip(sp_parts, pyfsr_parts):
            tp_param = tp.startswith("{") and tp.endswith("}")
            cp_param = cp.startswith("{") and cp.endswith("}")
            if tp_param and cp_param:
                continue  # both are params - match
            if tp_param:
                continue  # spec has {param}, pyfsr has literal - match (wildcard)
            if cp_param:
                continue  # pyfsr has {param}, spec has literal - match
            if tp != cp:
                ok = False
                break
        if ok:
            return sp
    return None


# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="Counts only.")
    ap.add_argument("--section", choices=["spec_no_pyfsr", "pyfsr_no_spec",
                                           "stale_samples", "pyfsr_summary"],
                    action="append", help="Show only the named section(s).")
    args = ap.parse_args()

    spec_ops = load_spec_ops()
    pyfsr_eps = load_pyfsr_endpoints()
    sample_keys, PYFSR_EXAMPLES, _generic_fallback, _KNOWN_COLLECTIONS = load_pyfsr_samples()

    spec_paths = set(spec_ops.keys())

    # --- Section 1: spec ops with no pyfsr sample ---------------------------
    # A spec op has a pyfsr sample if:
    #   (a) it's directly in PYFSR_EXAMPLES, or
    #   (b) it's a concrete collection path that falls back to a generic template.
    def _has_sample(op_key: str) -> bool:
        if op_key in sample_keys:
            return True
        http_method, path = op_key.split(" ", 1)
        fallback = _generic_fallback(http_method.lower(), path)
        if fallback and f"{fallback[0].upper()} {fallback[1]}" in sample_keys:
            return True
        return False

    spec_no_pyfsr = sorted(k for k in spec_paths if not _has_sample(k))

    # --- Section 2: pyfsr methods with no spec endpoint --------------------
    # A pyfsr endpoint matches a spec op if:
    #   (a) the exact template matches (including trailing-slash + /api/ai/
    #       prefix tolerance), or
    #   (b) the templates match structurally (same shape, different param names), or
    #   (c) a concrete pyfsr path matches a spec path template, or
    #   (d) a concrete collection path like /api/3/roles/{uuid} matches the
    #       generic template /api/3/{collection}/{uuid}.
    def _matches_spec(http_m: str, path: str) -> bool:
        path_n = _normalize_path(path)
        for sp_key in spec_paths:
            sp_http, sp_path = sp_key.split(" ", 1)
            if sp_http == http_m and _normalize_path(sp_path) == path_n:
                return True
        # Template-shape match (different param names: {alert_id} vs {uuid}).
        spec_paths_for_verb = {k.split(" ", 1)[1] for k in spec_paths
                               if k.startswith(http_m + " ")}
        spec_paths_for_verb_norm = {_normalize_path(sp) for sp in spec_paths_for_verb}
        if _match_template_to_template(path_n, spec_paths_for_verb_norm):
            return True
        # Concrete-to-template match (pyfsr uses real values, spec has {param}).
        if "{" not in path:
            if _match_concrete_to_template(path, spec_paths_for_verb_norm):
                return True
        return False

    pyfsr_no_spec: list[tuple[str, list[str]]] = []
    for ep_key, methods in sorted(pyfsr_eps.items()):
        if ep_key in spec_paths:
            continue
        http_m, path = ep_key.split(" ", 1)
        # Skip broken f-string resolutions (end with "{" or contain "{?").
        if path.endswith("{") or "{?" in path:
            continue
        if _matches_spec(http_m, path):
            continue
        pyfsr_no_spec.append((ep_key, methods))

    # --- Section 3: stale samples ------------------------------------------
    # A PYFSR_EXAMPLES key is stale if it doesn't match any spec op - exact,
    # trailing-slash-tolerant, prefix-normalized, or template-shape match.
    stale_samples = []
    for k in sorted(sample_keys):
        if k in spec_paths:
            continue
        http_m, path = k.split(" ", 1)
        if _matches_spec(http_m, path):
            continue
        stale_samples.append(k)

    # --- Print --------------------------------------------------------------
    sections = args.section or ["spec_no_pyfsr", "pyfsr_no_spec", "stale_samples",
                                "pyfsr_summary"]

    if "spec_no_pyfsr" in sections:
        n = len(spec_no_pyfsr)
        total = len(spec_paths)
        pct = (total - n) * 100 // total if total else 0
        if args.quiet:
            print(f"spec_no_pyfsr: {n}/{total} ({pct}% have pyfsr)")
        else:
            mark = "!" if n else "ok"
            print(f"\n[{mark}] spec_no_pyfsr - spec ops with no pyfsr sample: {n}/{total} ({pct}% covered)")
            for k in spec_no_pyfsr:
                print(f"    {k}")

    if "pyfsr_no_spec" in sections:
        n = len(pyfsr_no_spec)
        if args.quiet:
            print(f"pyfsr_no_spec: {n}")
        else:
            mark = "!" if n else "ok"
            print(f"\n[{mark}] pyfsr_no_spec - pyfsr methods hitting undocumented endpoints: {n}")
            for ep_key, methods in pyfsr_no_spec:
                print(f"    {ep_key:60}  <- {', '.join(methods)}")

    if "stale_samples" in sections:
        n = len(stale_samples)
        if args.quiet:
            print(f"stale_samples: {n}")
        else:
            mark = "!" if n else "ok"
            print(f"\n[{mark}] stale_samples - PYFSR_EXAMPLES entries not in spec: {n}")
            for k in stale_samples:
                print(f"    {k}")

    if "pyfsr_summary" in sections:
        total_methods = sum(len(v) for v in pyfsr_eps.values())
        print(f"\npyfsr_summary:")
        print(f"    spec ops:              {len(spec_paths)}")
        print(f"    pyfsr endpoints:       {len(pyfsr_eps)} distinct ({total_methods} method calls)")
        print(f"    PYFSR_EXAMPLES:        {len(sample_keys)}")
        print(f"    spec w/ pyfsr sample:  {len(spec_paths) - len(spec_no_pyfsr)}")
        print(f"    spec w/o pyfsr sample: {len(spec_no_pyfsr)}")
        print(f"    pyfsr w/o spec:        {len(pyfsr_no_spec)}")
        print(f"    stale samples:         {len(stale_samples)}")

    has_issues = bool(spec_no_pyfsr or pyfsr_no_spec or stale_samples)
    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
