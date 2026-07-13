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
import re

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
            src = f"print({src})"
        lines.append(src)

    body = "\n".join(lines)
    body = _DEMO_CLIENT_LINE_RE.sub("", body).strip("\n")
    return _PREAMBLE + body


def manual_example(body: str) -> str:
    """Hand-written fallback source for an op without a pyfsr doctest yet."""
    return _PREAMBLE + body


# (http_method, path) -> ("doctest", dotted-path) | ("manual", source-body)
#
# Keep "manual" entries to the minimum needed to cover an op with no pyfsr
# doctest; prefer adding the doctest upstream in pyfsr and switching to
# "doctest" over growing this list.
PYFSR_EXAMPLES: dict[tuple[str, str], tuple[str, str]] = {
    ("get", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records"),
    ("post", "/api/3/{collection}"): ("doctest", "pyfsr.records:RecordSet.create"),
    ("put", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records:RecordSet.update"),
    ("delete", "/api/3/{collection}/{uuid}"): ("doctest", "pyfsr.records:RecordSet.delete"),
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


def apply_pyfsr_samples(paths: dict) -> int:
    """Attach ``x-codeSamples`` to every op in ``paths`` (keyed by path -> {method: op})
    that has a ``PYFSR_EXAMPLES`` entry.

    Returns the count applied. Raises if extraction fails for any mapped
    entry -- a broken sample should fail the build, not ship silently broken.
    """
    applied = 0
    for path, path_item in paths.items():
        for http_method, op in path_item.items():
            if http_method not in _HTTP_METHODS:
                continue
            if (http_method, path) not in PYFSR_EXAMPLES:
                continue
            op["x-codeSamples"] = [build_pyfsr_sample(http_method, path)]
            applied += 1
    return applied
