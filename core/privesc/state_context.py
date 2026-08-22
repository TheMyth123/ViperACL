import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class Credential:
    """Represents a discovered or created authentication material."""
    username: str
    cred_type: str  # e.g., 'password', 'ntlm', 'ticket'
    value: str      # The actual password, hash, or base64 ticket

@dataclass
class RollbackAction:
    """Stores data required to revert an environment to its original state."""
    action_type: str      # e.g., 'REMOVE_MEMBER', 'RESTORE_DACL', 'FLAG_MANUAL_PW_RESET'
    target: str           # The DN or object affected
    original_state: Any   # The data needed to revert (e.g., original SDDL, old member list)
    description: str

class SessionContext:
    """
    Manages the current state, identity, and remediation logs 
    during an automated graph traversal.
    """
    def __init__(self, domain: str, dc_ip: str, initial_user: str, initial_password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        
        # Identity and Credentials
        self.current_identity: str = initial_user
        self.credentials: Dict[str, Credential] = {}
        
        # Remediation / Rollback Tracking (For Phase 4)
        self.rollback_log: List[RollbackAction] = []
        
        # Initialize with the starting user
        self.add_credential(initial_user, 'password', initial_password)
        logging.info(f"SessionContext initialized for {self.domain} starting as {initial_user}")

    def add_credential(self, username: str, cred_type: str, value: str) -> None:
        """
        Stores newly acquired credentials (e.g., from DCSync or ForceChangePassword).
        """
        self.credentials[username] = Credential(username, cred_type, value)
        logging.debug(f"Stored new {cred_type} for user: {username}")

    def get_credential(self, username: str) -> Optional[Credential]:
        """Retrieves known credentials for a specific user."""
        return self.credentials.get(username)

    def switch_identity(self, new_user: str) -> bool:
        """
        Switches the active context to a new user.
        Accepts common AD identity aliases such as UPN, SAM, and NetBIOS formats.
        """
        if not new_user:
            return False

        candidates = set()
        raw = str(new_user).strip()
        candidates.add(raw)

        if "\\" in raw:
            candidates.add(raw.split("\\")[-1])
        if "@" in raw:
            candidates.add(raw.split("@")[0])
            sam = raw.split("@")[0]
            if self.domain:
                netbios = self.domain.split(".")[0]
                candidates.add(f"{netbios}\\{sam}")
                candidates.add(f"{sam}@{self.domain}")
        else:
            sam = raw
            if self.domain:
                netbios = self.domain.split(".")[0]
                candidates.add(f"{netbios}\\{raw}")
                candidates.add(f"{raw}@{self.domain}")

        for candidate in candidates:
            if candidate in self.credentials:
                self.current_identity = candidate
                logging.info(f"Context switched. Now operating as: {self.current_identity}")
                return True

        logging.error(f"Cannot switch to {new_user}: No credentials in context.")
        return False

    def log_for_rollback(self, action_type: str, target: str, original_state: Any, description: str) -> None:
        """
        Logs a modification so that Phase 4 (Remediation) can revert it.
        
        Examples:
        - AddMember: Log the group and the fact that we added X, so Phase 4 removes X.
        - WriteDacl: Store the original Security Descriptor to re-apply it later.
        - ForceChangePassword: Log that it was changed (may require manual admin intervention to restore).
        """
        action = RollbackAction(
            action_type=action_type,
            target=target,
            original_state=original_state,
            description=description
        )
        self.rollback_log.append(action)
        logging.info(f"Rollback logged: {action_type} on {target}")

    def get_remediation_plan(self) -> List[RollbackAction]:
        """
        Returns the accumulated rollback log in reverse order (LIFO).
        Phase 4 should process these from last to first to safely unroll the changes.
        """
        return list(reversed(self.rollback_log))

    def get_current_auth(self) -> dict:
        """
        Helper to quickly grab the authentication details of the current active identity
        to pass into network/LDAP connections.
        """
        cred = self.get_credential(self.current_identity)
        if cred:
            return {
                "username": cred.username,
                "type": cred.cred_type,
                "value": cred.value,
                "domain": self.domain,
                "dc_ip": self.dc_ip
            }
        return {}