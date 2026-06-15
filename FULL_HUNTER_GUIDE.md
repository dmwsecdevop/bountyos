# BountyOS Full Hunter Guide

## What is integrated

1. **Program Radar and Opportunity Scorer** select promising authorized programs.
2. **Recon agents** populate scan events and findings.
3. **Attack Graph** connects targets, assets, endpoints, technologies, findings and hypotheses.
4. **Bug Hunter Brain** creates ranked hypotheses without claiming they are confirmed.
5. **Adaptive Planner** chooses the next action using expected value, effort, noise and past utility.
6. **Validation Engine** creates deterministic plans and approval gates.
7. **Evidence Store** redacts secrets and records SHA-256 hashes.
8. **Report Agent** produces Markdown, JSON and HTML submissions with quality checks.
9. **Experience Store** records action utility so later plans can improve.
10. **Digital Twin Labs** test the full pipeline without an external target.

## First test

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`, select **HUNTER**, and create the **SaaS API authorization lab**.
The lab is synthetic and exercises graph, hypotheses, planning, validation and reporting.

## Report exports

Generated reports are stored under:

```text
exports/reports/<report-id>.md
exports/reports/<report-id>.json
exports/reports/<report-id>.html
```

Set another directory with:

```bash
export BOUNTYOS_EXPORT_DIR=/path/to/exports
```
