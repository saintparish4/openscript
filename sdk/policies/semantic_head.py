"""Placeholder until tools/train_semantic_head.py writes the trained head."""

HEAD = {
    "model": "sentence-transformers/all-MiniLM-L6-v2",
    "labels": ["benign", "prompt_injection", "harmful_request", "toxicity"],
    "weights": [[0.0], [0.0], [0.0], [0.0]],
    "bias": [0.0, 0.0, 0.0, 0.0],
    "threshold": 1.0,
}
