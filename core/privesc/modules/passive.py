"""Compatibility handlers for passive SharpHound edges."""

import logging


class PassiveModule:
    def __init__(self, engine):
        self.engine = engine

    def execute(self, rel, context) -> bool:
        target = rel.end_node.get("name") or rel.end_node.get("distinguishedname")
        logging.info(f"PASSIVE: {rel.type} -> {target}; no action required.")
        return True
