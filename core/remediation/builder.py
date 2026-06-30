# core/remediation/builder.py
from . import ps_templates

class ScriptBuilder:
    def __init__(self):
        # Maps ViperACL relationship names to PowerShell ActiveDirectoryRights regex
        self.acl_mapping = {
            'GenericWrite': 'GenericWrite|WriteProperty', # Expanded to catch all Write variations
            'GenericAll': 'GenericAll',
            'AddMember': 'WriteProperty',
            'AllExtendedRights': 'ExtendedRight',
            'WriteDacl': 'WriteDacl',
            'WriteOwner': 'WriteOwner',
            'Owns': 'WriteOwner'
        }

    def get_remediation_block(self, rel_type: str, source: str, target: str) -> str:
        """
        Takes a relationship type and nodes, returns the compiled PowerShell snippet.
        """
        # Passive: Group Membership
        if rel_type == 'MemberOf':
            return ps_templates.REMOVE_GROUP_MEMBER.format(source=source, target=target)
        
        # Domain Level: DCSync
        elif rel_type in ['DCSync', 'GetChanges', 'GetChangesAll']:
            return ps_templates.REMOVE_DCSYNC.format(source=source, target=target)
            
        # Destructive: Actively Strip Password Reset Privilege
        elif rel_type == 'ForceChangePassword':
            return ps_templates.REMOVE_FORCE_CHANGE_PASSWORD.format(source=source, target=target)
            
        # Standard/Structural: General ACL modification
        elif rel_type in self.acl_mapping:
            ad_right = self.acl_mapping[rel_type]
            return ps_templates.REMOVE_GENERIC_ACL.format(
                source=source, 
                target=target, 
                ad_right=ad_right
            )
            
        else:
            return f"\nWrite-Host '[-] SKIPPED: Unsupported relationship type for auto-remediation: {rel_type}' -ForegroundColor DarkGray\n"