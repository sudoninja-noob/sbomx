"""File hashing helpers."""
from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(path: str | Path, algo: str = "sha256", chunk: int = 1 << 20) -> str:
    """Return the hex digest of a file for the given algorithm."""
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_file(path: str | Path) -> str:
    return hash_file(path, "sha256")


def sha512_file(path: str | Path) -> str:
    return hash_file(path, "sha512")
