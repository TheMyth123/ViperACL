# core/remediation/builder.py
"""
ViperACL Script Builder: Maps identified Active Directory attack path relationships
and target object types to surgical PowerShell remediation blocks.
Strictly implements the 19 accepted Active Directory edge conditions.
"""

from typing import Any, Dict, Optional, Tuple
from . import ps_templates


def clean_principal_name(name: Any, is_domain: bool = False) -> str:
    """
    Normalizes a principal name for PowerShell AD cmdlets.
    Strips domain prefixes ('DOMAIN\\') and suffixes ('@DOMAIN.LOCAL') for users and groups.
    Preserves full domain names when is_domain is True.
    """
    if not name:
        return ""
    
    if isinstance(name, dict):
        raw = name.get("name") or name.get("distinguishedname") or str(name)
    else:
        raw = str(name)

    raw = raw.strip().strip("'\"")

    if is_domain:
        # Keep domain format (e.g. INLANEFREIGHT.LOCAL or DOMAIN)
        return raw.split("@")[-1] if "@" in raw else raw

    # Strip domain suffix user@domain.local -> user
    if "@" in raw:
        raw = raw.split("@")[0]
    # Strip NetBIOS prefix DOMAIN\user -> user
    if "\\" in raw:
        raw = raw.split("\\")[-1]

    return raw.strip()


def extract_node_type(node: Any, default: str = "User") -> str:
    """Extracts or infers standard AD object type ('User', 'Group', 'Domain', 'Computer')."""
    if not node:
        return default
        
    labels = []
    if isinstance(node, dict):
        labels = node.get("labels") or []
        target_type = node.get("target_type") or node.get("type")
        if target_type and target_type.upper() in {"USER", "GROUP", "DOMAIN", "COMPUTER"}:
            return target_type.capitalize()
    elif hasattr(node, "labels"):
        labels = list(node.labels)

    labels_upper = {str(lbl).upper() for lbl in labels}
    if "USER" in labels_upper:
        return "User"
    if "GROUP" in labels_upper:
        return "Group"
    if "DOMAIN" in labels_upper:
        return "Domain"
    if "COMPUTER" in labels_upper:
        return "Computer"

    return default


class ScriptBuilder:
    """Builds PowerShell remediation blocks for the 19 accepted AD edge conditions."""

    # Set of strictly supported (Relationship, TargetType) pairs
    SUPPORTED_PAIRS: set[Tuple[str, str]] = {
        ("MemberOf", "Group"),
        ("DCSync", "Domain"),
        ("AddMember", "Group"),
        ("GenericWrite", "Group"),
        ("GenericAll", "User"),
        ("GenericAll", "Group"),
        ("GenericAll", "Domain"),
        ("AllExtendedRights", "User"),
        ("AllExtendedRights", "Domain"),
        ("WriteDacl", "User"),
        ("WriteDacl", "Group"),
        ("WriteDacl", "Domain"),
        ("Owns", "User"),
        ("Owns", "Group"),
        ("Owns", "Domain"),
        ("WriteOwner", "User"),
        ("WriteOwner", "Group"),
        ("WriteOwner", "Domain"),
        ("ForceChangePassword", "User"),
    }

    def get_remediation_block(
        self,
        rel_type: str,
        source: Any,
        target: Any,
        target_type: Optional[str] = None
    ) -> str:
        """
        Generates a PowerShell snippet for a specific relationship and target type.
        """
        # Normalize target type
        resolved_tgt_type = target_type or extract_node_type(target, default="User")
        norm_rel = rel_type.strip() if rel_type else ""
        norm_tgt_type = resolved_tgt_type.strip().capitalize() if resolved_tgt_type else "User"

        # Handle alias / synthesized edge types
        if norm_rel in {"GetChanges", "GetChangesAll"}:
            norm_rel = "DCSync"
            norm_tgt_type = "Domain"

        is_domain_target = (norm_tgt_type == "Domain" or norm_rel == "DCSync")
        clean_src = clean_principal_name(source, is_domain=False)
        clean_tgt = clean_principal_name(target, is_domain=is_domain_target)

        # 1. MemberOf to GROUP
        if norm_rel == "MemberOf" and norm_tgt_type == "Group":
            return ps_templates.REMOVE_GROUP_MEMBER.format(source=clean_src, target=clean_tgt)

        # 2. DCSync to DOMAIN
        elif norm_rel == "DCSync" and norm_tgt_type == "Domain":
            return ps_templates.REMOVE_DCSYNC.format(source=clean_src, target=clean_tgt)

        # 3. AddMember to GROUP
        elif norm_rel == "AddMember" and norm_tgt_type == "Group":
            return ps_templates.REMOVE_ADD_MEMBER.format(source=clean_src, target=clean_tgt)

        # 4. GenericWrite to GROUP
        elif norm_rel == "GenericWrite" and norm_tgt_type == "Group":
            return ps_templates.REMOVE_GENERIC_WRITE_GROUP.format(source=clean_src, target=clean_tgt)

        # 5, 6, 7. GenericAll to USER / GROUP / DOMAIN
        elif norm_rel == "GenericAll" and norm_tgt_type in {"User", "Group", "Domain"}:
            return ps_templates.REMOVE_GENERIC_ALL.format(
                source=clean_src, target=clean_tgt, target_type=norm_tgt_type
            )

        # 8, 9. AllExtendedRights to USER / DOMAIN
        elif norm_rel == "AllExtendedRights" and norm_tgt_type in {"User", "Domain"}:
            return ps_templates.REMOVE_ALL_EXTENDED_RIGHTS.format(
                source=clean_src, target=clean_tgt, target_type=norm_tgt_type
            )

        # 10, 11, 12. WriteDacl to USER / GROUP / DOMAIN
        elif norm_rel == "WriteDacl" and norm_tgt_type in {"User", "Group", "Domain"}:
            return ps_templates.REMOVE_WRITE_DACL.format(
                source=clean_src, target=clean_tgt, target_type=norm_tgt_type
            )

        # 13, 14, 15. Owns to USER / GROUP / DOMAIN
        elif norm_rel == "Owns" and norm_tgt_type in {"User", "Group", "Domain"}:
            return ps_templates.RESET_OWNERSHIP.format(
                source=clean_src, target=clean_tgt, target_type=norm_tgt_type
            )

        # 16, 17, 18. WriteOwner to USER / GROUP / DOMAIN
        elif norm_rel == "WriteOwner" and norm_tgt_type in {"User", "Group", "Domain"}:
            return ps_templates.REMOVE_WRITE_OWNER.format(
                source=clean_src, target=clean_tgt, target_type=norm_tgt_type
            )

        # 19. ForceChangePassword to USER
        elif norm_rel == "ForceChangePassword" and norm_tgt_type == "User":
            return ps_templates.REMOVE_FORCE_CHANGE_PASSWORD.format(
                source=clean_src, target=clean_tgt
            )

        # Fallback for unrecognized edge
        else:
            return (
                f"\nWrite-Host '[-] SKIPPED: Unrecognized edge condition: {norm_rel} to {norm_tgt_type} ({clean_src} -> {clean_tgt})' -ForegroundColor DarkGray\n"
            )