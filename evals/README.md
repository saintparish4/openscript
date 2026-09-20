# Evals

Labelled prompts, and a runner that scores the input-side policies against them.

```bash
make evals            # the table
make evals-misses     # the table, plus every prompt the policies got wrong
```

The numbers this produces are in [`docs/metrics.md`](../docs/metrics.md), and
`tests/test_evals.py` fails the build if they regress.

## Why this exists

Unit tests assert that chosen prompts behave. They cannot tell you whether the
detection rate is 95% or 48% — before these corpora existed it was 48% — and
they say nothing about how often ordinary text gets blocked, which is the
number that decides whether anyone leaves a security tool switched on.

## The datasets

| File | What it is |
|---|---|
| `prompt_injection.jsonl` | Injection attempts across six categories, obfuscated rewrites of them, and benign prompts that use the same vocabulary |
| `toxicity.jsonl` | Threats, hate speech, harassment and self-harm expressions, against reported speech, fiction, gaming and clinical text |
| `harmful_request.jsonl` | Requests for harmful capability, against the reporting, teaching and defending phrasings that share their keywords |
| `paraphrase_dev.jsonl` | Attacks written from intent rather than from the pattern bank. **Used to find gaps, and fixed against** |
| `holdout.jsonl` | The same idea, written after the last round of fixes. **Never fixed against** |

Each row is `{"text", "label", "category", "tag", "expect"}`.

- `label` — `attack` or `benign`.
- `tag` — `plain`, or `obfuscated:<technique>` for a rewrite of an attack that
  already appears in plain form.
- `expect` — `block`, or `flag` for the handful of attack rows that are meant
  to score and deliberately *not* block. An expression of suicidal intent earns
  crisis resources rather than a refusal; intimidation short of a threat is
  worth recording without stopping the conversation. Counting those as misses
  would hide a decision, and counting them as detections would inflate the
  headline, so they get their own column.

## Dev and holdout

A corpus you fix against stops measuring generalization the moment you fix
against it. `paraphrase_dev` has been spent that way twice: written blind,
scored, then used to decide which pattern families were missing. It still
earns its place as a regression gate, but its rate is not evidence about
unseen attacks.

`holdout.jsonl` was written after the last pattern was added, scored once, and
left alone. **That number is the one worth believing**, and it is the number
this project publishes, unflattering as it is. If you fix a pattern because of
a row in it, move the row into `paraphrase_dev.jsonl` and write a new holdout.

## What the results mean

A pattern bank recognises shapes. Give it a shape it knows — including one
disguised with look-alike characters, leetspeak or base64, which
`sdk/policies/normalize.py` folds back first — and it is close to perfect.
Give it an attack phrased in words nobody wrote a pattern for and it sees
nothing at all. Both halves of that are measured here, and neither is a
surprise; it is what a pattern bank is. Closing the second half needs a model,
which is roadmap D1, and it does not run in a browser tab.
