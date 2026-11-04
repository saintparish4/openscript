# Amendment 3, deviation 1: the serving image

Written and frozen 2026-11-04, after the first pod and before any request to
the model. Amendment 3 is unchanged except for what this file says.

## What happened

The first pod (`1vecfnllxqxo28`, RTX 4090, Secure Cloud) was still fetching
`vllm/vllm-openai:v0.8.5` from Docker Hub 17.5 minutes after it was created.
It had not started its container, so the model had not been downloaded and
no request had been sent. It was terminated. Its pod time counts against the
$5.00 budget.

The pod's own read listed it at **$0.89 an hour**, not the $0.34 the capacity
read showed. That figure was the lowest rate across clouds. Amendment 3's
budget is in dollars, so it stands. At $0.89 an hour it buys about 5.6 hours.

## What changes

- **The image** is `runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404`,
  RunPod's official PyTorch 2.8 template image, taken from the
  public-templates read.
- **vLLM** is installed into it at boot as `vllm==0.10.2`, and then started
  as `vllm serve` with the same model, arguments and key as amendment 3.

Nothing else changes: the model, its weights, the tool-call parser, the
context length, temperature 0, the suites, the runs, the ledger, what is
reported, and the budget. The vLLM version is newer. Its effect on the
model's choices is not measured here, and it is reported as part of the
setup.
