"""Shared path normalization helpers for privesc execution."""

from __future__ import annotations

from typing import Any


def path_to_sequence(path: Any) -> list[Any]:
    """Convert a saved path payload into the flat node/relationship sequence used by privesc."""
    if isinstance(path, dict):
        sequence = path.get("sequence")
        if sequence:
            return sequence

        steps = path.get("steps")
        if steps:
            sequence: list[Any] = []
            for step in steps:
                sequence.append(step.get("source", {}))
                sequence.append(step.get("relationship"))
                sequence.append(step.get("target", {}))
            return sequence

        raise ValueError("Path payload is missing a valid steps or sequence representation")

    if isinstance(path, list):
        if path and isinstance(path[0], dict) and "source" in path[0]:
            sequence: list[Any] = []
            for step in path:
                sequence.append(step.get("source", {}))
                sequence.append(step.get("relationship"))
                sequence.append(step.get("target", {}))
            return sequence
        return path

    raise ValueError("Unsupported path format: expected list or saved path dict")