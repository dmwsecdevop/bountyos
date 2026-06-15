# BountyOS Agent Quality Loop

The quality loop evaluates real workflow records, not an agent's self-description.

## What is evaluated

- Bug Hunter hypotheses
- Adaptive planner decisions
- Exploit-validation results
- Bounty reports

## Scores

Every output receives 0–100 scores for evidence quality, accuracy, reproducibility,
impact confidence, efficiency, and safety. The engine also calculates a calibrated
confidence and returns one of:

- `accepted`
- `accepted_with_warnings`
- `retry`
- `rejected`

## Controlled retry

Weak hypotheses and plans may be regenerated. Weak reports may be rebuilt from the
same evidence. Validation retries only prepare another approval-gated attempt; they
never send active requests automatically.

## Chat commands

- `evaluate agent work`
- `show quality scores`
- `show model performance`
- `retry weak work`
