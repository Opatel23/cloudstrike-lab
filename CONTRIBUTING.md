# Contributing to CloudStrike Lab

CloudStrike Lab prioritizes safety, reproducibility, and evidence-backed results. Contributions should preserve those properties.

## Development setup

From the repository root:

```powershell
python -m pip install -e ".[dev]"
$env:PYTHONPATH = "$PWD\engine"
python -m unittest discover -s tests -v
```

For dashboard work:

```powershell
cd dashboard
pnpm install
pnpm lint
pnpm build
```

## Pull-request checklist

- Keep the fixture-backed demo deterministic and offline.
- Add tests for graph, simulation, detection, remediation, or safety behavior.
- Do not weaken account, tag, resource-prefix, or manifest validation.
- Do not add generic arbitrary-command, arbitrary-target, or unrestricted AWS execution.
- Update the report schema and dashboard together when either changes.
- Run the Python tests, linter, and dashboard build before submitting.

## Scenario requirements

New scenarios must define an authorized lab boundary, synthetic targets, explicit safety invariants, expected telemetry, deterministic remediation, and a before/after replay assertion. A scenario is not complete merely because a path is theoretically possible.
