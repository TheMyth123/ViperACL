"""
ViperACL - Abuse Module

This module handles the confirmation and exploitation of ACL paths found by the pathfinder.
After finding a potential path, we need to:
1. Confirm the path by actually abusing the misconfigured ACL
2. Extract hashes/passwords to verify the exploit works
3. Only then generate remediation PowerShell scripts

Workflow:
    Path Found → Confirm/Abuse → Extract Credentials → Generate Remediation
"""

from .confirm import PathConfirmer
from .extract import CredentialExtractor

__all__ = ['PathConfirmer', 'CredentialExtractor']