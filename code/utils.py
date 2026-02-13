"""Utility functions."""

import hashlib
import json
from pathlib import Path

def compute_hash(text: str) -> str:
    """Compute SHA256 hash of a string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def load_jsonl(path: Path):
    """Load a JSONL file line by line."""
    with open(path, 'r') as f:
        for line in f:
            if line.strip():
                yield json.loads(line)

def save_jsonl(data, path: Path):
    """Save list of dicts as JSONL."""
    with open(path, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')
