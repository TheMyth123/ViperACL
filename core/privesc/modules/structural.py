"""Compatibility handlers for structural SharpHound edges."""

import logging


class StructuralModule:
    def __init__(self, engine):
        self.engine = engine

    def execute(self, rel, context) -> bool:
        target = rel.end_node.get("name") or rel.end_node.get("distinguishedname")
        logging.info(f"STRUCTURAL: {rel.type} -> {target}; no direct exploit mapped yet.")
        return True
