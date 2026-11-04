# Amendment 3, deviation 3: hf_transfer installed at boot

Written and frozen 2026-11-04, before any request to the model.

After deviation 2 the third pod got past the tokenizer error. It then failed
to download the model: RunPod's PyTorch image sets
`HF_HUB_ENABLE_HF_TRANSFER=1`, and the `hf_transfer` package was not
installed (`ValueError: Fast download using 'hf_transfer' is enabled ... but
'hf_transfer' package is not available`). The boot command now installs
`hf_transfer` as well. It changes how the weights are downloaded, not which
weights. Nothing else changes.
