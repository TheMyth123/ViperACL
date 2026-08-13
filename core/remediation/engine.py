import os
from datetime import datetime
from .builder import ScriptBuilder
from . import ps_templates

class RemediationEngine:
    def __init__(self, output_dir="data/scripts"):
        self.output_dir = output_dir
        self.builder = ScriptBuilder()
        self.last_output_path = None

    def generate_script(self, remediation_targets: list) -> bool:
        """
        Takes a list of relationships and writes a unified PowerShell script.
        Expected format: [{'type': 'GenericAll', 'source': 'UserA', 'target': 'GroupB'}, ...]
        """
        self.last_output_path = None

        if not remediation_targets:
            print("[-] No relationships provided for remediation.")
            return False

        print(f"[*] Generating remediation script with {len(remediation_targets)} actions...")
        
        script_content = [ps_templates.HEADER]

        for idx, task in enumerate(remediation_targets, 1):
            rel_type = task.get('type')
            source = task.get('source')
            target = task.get('target')

            if not all([rel_type, source, target]):
                print(f"  [-] Skipping invalid task {idx}: Missing required fields.")
                continue

            # Add a visual separator for the script
            script_content.append(f"\n# --- Action {idx}: Mitigate {rel_type} ---")
            
            # Fetch and append the block
            block = self.builder.get_remediation_block(rel_type, source, target)
            script_content.append(block)

        script_content.append(ps_templates.FOOTER)

        # 1. Generate a meaningful filename using a timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"remediation_plan_{timestamp}.ps1"
        output_path = os.path.join(self.output_dir, filename)

        # 2. Ensure the 'scripts/' directory exists safely
        os.makedirs(self.output_dir, exist_ok=True)

        # 3. Write to file
        try:
            with open(output_path, "w") as f:
                f.write("".join(script_content))
            self.last_output_path = os.path.abspath(output_path)
            print(f"[+] Remediation script successfully saved to: {os.path.abspath(output_path)}")
            return True
        except Exception as e:
            print(f"[!] Failed to write script: {e}")
            return False