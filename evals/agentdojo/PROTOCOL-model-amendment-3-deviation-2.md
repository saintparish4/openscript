# Amendment 3, deviation 2: transformers pinned, and two pods that never ran

Written and frozen 2026-11-04, before any request to the model. Amendment 3
and deviation 1 are unchanged except for what this file says.

## What happened

- **The second pod never started its container.** That was
  `r5qfewimp20ebn`, on a machine whose Docker daemon refused the create
  twice, once by timing out and once on a restart. It was terminated.
- **The third pod started but crash-looped.** That is `vt40azzfuwgjba`, in
  EU-RO-1. `pip install vllm==0.10.2` pulled a transformers release whose
  Qwen2 tokenizer has no `all_special_tokens_extended`, and vLLM raised
  `AttributeError` on start, before it served anything.

No request reached a model on any pod. Their time counts against the $5.00
budget.

## What changes

The boot command installs `transformers==4.56.2` beside `vllm==0.10.2`.
Nothing else changes.
