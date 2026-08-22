# core/remediation/engine.py
"""
ViperACL Surgical Remediation Engine.
Takes selected attack path edges and generates production-ready, standalone
PowerShell scripts with detailed execution feedback and forensic evidence.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import ps_templates
from .builder import ScriptBuilder, clean_principal_name


class RemediationEngine:
    def __init__(self, output_dir: str = "data/scripts"):
        self.output_dir = Path(output_dir)
        self.builder = ScriptBuilder()
        self.last_output_path: Optional[str] = None
        self.last_script_content: Optional[str] = None

    def generate_script(
        self,
        remediation_targets: List[Dict[str, Any]],
        project_name: str = "Active Directory Security Assessment",
        domain: str = "Target Active Directory Domain",
        project_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Takes a list of selected relationships/edges and writes a unified PowerShell script.
        Expected target format:
        [
            {
                'type': 'GenericAll', # or 'relationship'
                'source': 'UserA' or {'name': 'UserA@DOMAIN'},
                'target': 'GroupB' or {'name': 'GroupB@DOMAIN'},
                'target_type': 'Group',
                'index': 0 # optional hop index
            }, ...
        ]
        """
        self.last_output_path = None
        self.last_script_content = None

        if not remediation_targets:
            return {
                "success": False,
                "error": "No remediation actions were selected for compilation.",
                "target_count": 0,
            }

        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        file_timestamp = now.strftime("%Y%m%d_%H%M%S")

        # 1. Format Header
        header = ps_templates.HEADER.format(
            project_name=project_name,
            timestamp=timestamp_str,
            domain=domain,
            action_count=len(remediation_targets),
        )
        script_parts = [header]

        # 2. Append Each Action Block
        valid_actions_count = 0
        for idx, task in enumerate(remediation_targets, 1):
            rel_type = task.get("type") or task.get("relationship") or ""
            source = task.get("source")
            target = task.get("target")
            target_type = task.get("target_type") or task.get("targetType")

            if not rel_type or source is None or target is None:
                continue

            src_display = clean_principal_name(source)
            tgt_display = clean_principal_name(target, is_domain=(target_type == "Domain"))

            script_parts.append(
                f"\n# ========================================================="
                f"\n# Action {idx}: Neutralize {rel_type} on {target_type or 'Object'}"
                f"\n# Route Flaw: {src_display} --[{rel_type}]--> {tgt_display}"
                f"\n# ========================================================="
            )

            block = self.builder.get_remediation_block(
                rel_type=rel_type,
                source=source,
                target=target,
                target_type=target_type,
            )
            script_parts.append(block)
            valid_actions_count += 1

        if valid_actions_count == 0:
            return {
                "success": False,
                "error": "None of the selected edges could be parsed into valid remediation actions.",
                "target_count": 0,
            }

        # 3. Append Footer
        script_parts.append(ps_templates.FOOTER)
        full_script = "".join(script_parts)

        # 4. Determine Filename and Output Path
        filename = f"remediation_plan_{file_timestamp}.ps1"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / filename

        # 5. Write to File
        try:
            output_file.write_text(full_script, encoding="utf-8")
            self.last_output_path = str(output_file.resolve())
            self.last_script_content = full_script
            file_size = output_file.stat().st_size

            rel_path = str(output_file)
            if project_root:
                try:
                    rel_path = str(output_file.relative_to(project_root))
                except ValueError:
                    pass

            return {
                "success": True,
                "filename": filename,
                "output_path": str(output_file.resolve()),
                "relative_path": rel_path,
                "file_size": file_size,
                "target_count": valid_actions_count,
                "script_content": full_script,
                "created_at": timestamp_str,
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Failed to write PowerShell script to disk: {exc}",
                "target_count": valid_actions_count,
            }