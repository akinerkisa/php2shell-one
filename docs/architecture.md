# Design and execution paths

- `patchproof` remains the original verification engine with a version-policy dataset and Linux/runtime probes. Legacy command still works.
- `php2shellkit.cli` adds user-facing subcommands with consistent text/JSON/SARIF/CSV/HTML output for heuristic modules.
- `hunt.py`: offline access, PHP error and JSONL process event analysis; deterministic IP aliasing; optional curated IOC file.
- `repoaudit.py`: Dockerfile / Compose tag inspection without invoking Docker/registry.
- `configcheck.py`: ini and pool-file heuristics; no runtime configuration claims.
- `webcheck.py`: opt-in single-target HEAD; no redirects and no body.
- `common.py`: report envelopes, per-finding source/line evidence, text/JSON/SARIF/HTML/CSV rendering.

The response-kit package has no runtime third-party Python dependencies. Template rules are shown verbatim; **nothing is deployed automatically**. `verify --docker-image` requires local Docker daemon and never starts its created container. Reports are generated locally; there is no telemetry service or credential collection.

## Extension path

Contributors can add a vendor policy only with official citations, version-comparison tests and false-assurance edge cases. For detectors, require benign positive/negative fixtures, data-minimizing evidence, false positive notes, bounded processing, and no exploit sample.
