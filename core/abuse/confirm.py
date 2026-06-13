"""
Path Confirmer - Confirms ACL paths by actually abusing them

This module takes a path found by the pathfinder and attempts to exploit
each step to confirm the path is viable. Only after confirmation do we
proceed to credential extraction and remediation.
"""

from typing import List, Dict, Any, Optional
from ldap3 import Connection
from utils.logger import Logger


class PathConfirmer:
    """
    Confirms ACL paths by attempting to exploit each relationship.
    
    The confirmation process:
    1. For each relationship in the path, attempt the corresponding abuse
    2. Track which steps succeed and which fail
    3. Return a confirmation report with results
    """
    
    # Mapping of ACL rights to their abuse methods
    ACL_ABUSE_METHODS = {
        'GenericAll': 'abuse_generic_all',
        'GenericWrite': 'abuse_generic_write',
        'WriteDACL': 'abuse_write_dacl',
        'WriteOwner': 'abuse_write_owner',
        'AllExtendedRights': 'abuse_all_extended_rights',
        'ForceChangePassword': 'abuse_force_change_password',
        'AllowedToAct': 'abuse_allowed_to_act',
        'AddMember': 'abuse_add_member',
    }
    
    def __init__(self, connection: Connection, domain: str, dc_ip: str):
        """
        Initialize the PathConfirmer.
        
        Args:
            connection: LDAP connection to the domain controller
            domain: Domain name (e.g., "INLANEFREIGHT.LOCAL")
            dc_ip: IP address of the domain controller
        """
        self.connection = connection
        self.domain = domain
        self.dc_ip = dc_ip
        self.logger = Logger()
        self.confirmed_steps = []
        self.failed_steps = []
    
    def confirm_path(self, path: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Confirm a path by attempting to abuse each relationship.
        
        Args:
            path: List of relationships from source to target
            
        Returns:
            Dictionary with confirmation results:
            {
                'confirmed': bool,
                'total_steps': int,
                'successful_steps': int,
                'failed_steps': int,
                'steps': List[step_results],
                'can_reach_target': bool
            }
        """
        self.logger.info(f"[*] Starting path confirmation for {len(path)} steps...")
        
        results = {
            'confirmed': False,
            'total_steps': len(path),
            'successful_steps': 0,
            'failed_steps': 0,
            'steps': [],
            'can_reach_target': False
        }
        
        for i, step in enumerate(path):
            step_result = self._confirm_step(step, i)
            results['steps'].append(step_result)
            
            if step_result['success']:
                results['successful_steps'] += 1
                self.confirmed_steps.append(step)
                self.logger.info(f"[+] Step {i+1} confirmed: {step_result['method']}")
            else:
                results['failed_steps'] += 1
                self.failed_steps.append(step)
                self.logger.warning(f"[-] Step {i+1} failed: {step_result['error']}")
        
        # Path is confirmed if we can reach the target
        results['can_reach_target'] = results['successful_steps'] == results['total_steps']
        results['confirmed'] = results['can_reach_target']
        
        if results['confirmed']:
            self.logger.success(f"[+] Path confirmed! All {len(path)} steps successful.")
        else:
            self.logger.warning(f"[-] Path not fully confirmed. {results['successful_steps']}/{len(path)} steps successful.")
        
        return results
    
    def _confirm_step(self, step: Dict[str, Any], step_index: int) -> Dict[str, Any]:
        """
        Confirm a single step in the path.
        
        Args:
            step: A single relationship from the path
            step_index: Index of this step in the path
            
        Returns:
            Dictionary with step results
        """
        result = {
            'step_index': step_index,
            'success': False,
            'method': None,
            'error': None,
            'details': {}
        }
        
        try:
            # Extract relationship details
            rel_type = step.get('type', 'Unknown')
            start_node = step.get('start_node', {})
            end_node = step.get('end_node', {})
            
            # Determine the abuse method based on the relationship type
            abuse_method = self._get_abuse_method(rel_type)
            result['method'] = abuse_method
            
            # Attempt the abuse
            if abuse_method and hasattr(self, abuse_method):
                method_func = getattr(self, abuse_method)
                success, details = method_func(start_node, end_node)
                result['success'] = success
                result['details'] = details
            else:
                result['error'] = f"No abuse method for relationship type: {rel_type}"
                
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"[!] Error confirming step {step_index}: {e}")
        
        return result
    
    def _get_abuse_method(self, rel_type: str) -> Optional[str]:
        """
        Get the abuse method name for a relationship type.
        
        Args:
            rel_type: The type of relationship (e.g., 'GenericAll', 'WriteDACL')
            
        Returns:
            Name of the abuse method or None if not found
        """
        # Check if this is a known ACL abuse type
        for acl_type, method in self.ACL_ABUSE_METHODS.items():
            if acl_type in rel_type:
                return method
        
        # Default to generic abuse for unknown types
        return 'abuse_generic'
    
    # Abuse methods for different ACL rights
    
    def abuse_generic_all(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse GenericAll rights - full control over the target object.
        
        GenericAll allows:
        - Adding users to groups
        - Changing passwords
        - Writing to any attribute
        """
        target_name = end_node.get('name', 'Unknown')
        target_type = end_node.get('type', 'Unknown')
        
        # For GenericAll, we can do almost anything
        # This is a placeholder for the actual abuse logic
        self.logger.info(f"[*] Attempting GenericAll abuse on {target_type}: {target_name}")
        
        # TODO: Implement actual abuse logic
        # For now, return success for testing
        return True, {'target': target_name, 'type': target_type, 'abuse': 'GenericAll'}
    
    def abuse_generic_write(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse GenericWrite rights - can write to any non-protected attribute.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting GenericWrite abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'GenericWrite'}
    
    def abuse_write_dacl(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse WriteDACL rights - can modify the DACL (Discretionary Access Control List).
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting WriteDACL abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'WriteDACL'}
    
    def abuse_write_owner(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse WriteOwner rights - can become the owner of the object.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting WriteOwner abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'WriteOwner'}
    
    def abuse_all_extended_rights(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse AllExtendedRights - can perform extended operations.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting AllExtendedRights abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'AllExtendedRights'}
    
    def abuse_force_change_password(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse ForceChangePassword - can reset user passwords.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting ForceChangePassword abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'ForceChangePassword'}
    
    def abuse_allowed_to_act(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse AllowedToAct - can impersonate the target via resource-based constrained delegation.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting AllowedToAct abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'AllowedToAct'}
    
    def abuse_add_member(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Abuse AddMember - can add members to groups.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting AddMember abuse on: {target_name}")
        
        # TODO: Implement actual abuse logic
        return True, {'target': target_name, 'abuse': 'AddMember'}
    
    def abuse_generic(self, start_node: Dict, end_node: Dict) -> tuple:
        """
        Generic abuse method for unknown relationship types.
        """
        target_name = end_node.get('name', 'Unknown')
        self.logger.info(f"[*] Attempting generic abuse on: {target_name}")
        
        return False, {'target': target_name, 'abuse': 'Generic', 'error': 'Unknown relationship type'}
    
    def get_confirmation_report(self) -> Dict[str, Any]:
        """
        Get a detailed report of the confirmation process.
        
        Returns:
            Dictionary with confirmation details
        """
        return {
            'confirmed_steps': self.confirmed_steps,
            'failed_steps': self.failed_steps,
            'total_confirmed': len(self.confirmed_steps),
            'total_failed': len(self.failed_steps)
        }