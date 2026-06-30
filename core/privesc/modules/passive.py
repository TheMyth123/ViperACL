"""Compatibility handlers for passive SharpHound edges."""

import logging

from .shared import PrivescActions


class PassiveModule:
    def __init__(self, engine):
        self.engine = engine
        self.actions = PrivescActions(engine)

    # DCSync / GetChanges / GetChangesAll are treated as passive rights abuse.
    def execute(self, rel, context) -> bool:
        if rel.type in ("DCSync", "GetChanges", "GetChangesAll"):
            current_auth = context.get_current_auth()
            current_password = current_auth.get("value")
            if not current_password:
                logging.error("PASSIVE: no current password available for DCSync.")
                return False
            return self.actions.dcsync(current_password)

        start_node, end_node = self.actions.get_edge_nodes(rel)
        target = end_node.get("name") or end_node.get("distinguishedname") or start_node.get("name") or start_node.get("distinguishedname")
        logging.info(f"PASSIVE: {rel.type} -> {target}; no action required.")
        return True
