# BountyOS Runner Bridge

This build supports three execution modes:

- `local`: execute tools installed inside Cloud Run.
- `remote`: require a connected Linux/Parrot/worker runner.
- `hybrid`: prefer a connected runner and fall back to Cloud Run.

## Connect Parrot OS

1. Deploy this build.
2. Open **RUNNERS** in BountyOS.
3. Create a runner and copy the one-time token.
4. Copy this project folder or only `runner/` and `scripts/install_runner_service.sh` to Parrot.
5. Run the generated installation command.

The runner connects outbound over WSS. It never opens an inbound listener.

## Connect the GCP worker VM

Install tools:

```bash
sudo bash scripts/install_worker_tools.sh
```

Then create a runner in the dashboard and install the same runner service on the VM using label `worker,gcp`.

## Cloud Run deployment

The direct WebSocket gateway keeps active connections in process memory. This deployment script intentionally sets one warm Cloud Run instance:

```bash
./scripts/deploy_cloud_run_runner.sh --no-traffic --tag runner-test
```

The runner reconnects after Cloud Run closes or rotates a WebSocket. For multi-instance production, replace the in-memory gateway with Redis/Pub/Sub routing.

## Verified evidence

Remote tool output is stored as `ToolJob.output` and streamed into normal scan events. AI hypotheses remain separate from tool-backed findings.
