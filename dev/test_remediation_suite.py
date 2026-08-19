"""
Comprehensive Unit & Integration Test Suite for ViperACL Tab 4 Remediation.
Tests:
1. All 19 Recognized Active Directory Edge Conditions in ScriptBuilder.
2. RemediationEngine PowerShell script file generation and formatting.
3. ProjectManager remediation script archiving and persistence in projects.json.
4. FastAPI endpoints: /api/remediation/generate, /api/remediation/scripts, /api/remediation/scripts/{id}, and /api/remediation/scripts/{id}/download.
"""

import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

# Force search path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient

from core.projects import ProjectManager
from core.remediation.builder import ScriptBuilder, clean_principal_name, extract_node_type
from core.remediation.engine import RemediationEngine
from web.app import create_app


class TestScriptBuilder19Rules(unittest.TestCase):
    def setUp(self):
        self.builder = ScriptBuilder()

    def test_clean_principal_name(self):
        self.assertEqual(clean_principal_name("WLEY@INLANEFREIGHT.LOCAL"), "WLEY")
        self.assertEqual(clean_principal_name("INLANEFREIGHT\\WLEY"), "WLEY")
        self.assertEqual(clean_principal_name("WLEY"), "WLEY")
        self.assertEqual(clean_principal_name({"name": "ADUNN@DOMAIN.LOCAL"}), "ADUNN")
        # Domain target preservation
        self.assertEqual(clean_principal_name("INLANEFREIGHT.LOCAL", is_domain=True), "INLANEFREIGHT.LOCAL")
        self.assertEqual(clean_principal_name("DC01@INLANEFREIGHT.LOCAL", is_domain=True), "INLANEFREIGHT.LOCAL")

    def test_extract_node_type(self):
        self.assertEqual(extract_node_type({"labels": ["User", "Base"]}), "User")
        self.assertEqual(extract_node_type({"labels": ["Group", "Base"]}), "Group")
        self.assertEqual(extract_node_type({"labels": ["Domain", "Base"]}), "Domain")
        self.assertEqual(extract_node_type({"target_type": "Group"}), "Group")

    def test_all_19_recognized_conditions(self):
        """Test each of the 19 recognized edge conditions generates valid PowerShell."""
        test_cases = [
            # 1. MemberOf to GROUP
            ("MemberOf", "Group", "Remove-ADGroupMember"),
            # 2. DCSync to DOMAIN
            ("DCSync", "Domain", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
            # 3. AddMember to GROUP
            ("AddMember", "Group", "WriteProperty"),
            # 4. GenericWrite to GROUP
            ("GenericWrite", "Group", "GenericWrite"),
            # 5. GenericAll to USER
            ("GenericAll", "User", "GenericAll"),
            # 6. GenericAll to GROUP
            ("GenericAll", "Group", "GenericAll"),
            # 7. GenericAll to DOMAIN
            ("GenericAll", "Domain", "GenericAll"),
            # 8. AllExtendedRights to USER
            ("AllExtendedRights", "User", "ExtendedRight"),
            # 9. AllExtendedRights to DOMAIN
            ("AllExtendedRights", "Domain", "ExtendedRight"),
            # 10. WriteDacl to USER
            ("WriteDacl", "User", "WriteDacl"),
            # 11. WriteDacl to GROUP
            ("WriteDacl", "Group", "WriteDacl"),
            # 12. WriteDacl to DOMAIN
            ("WriteDacl", "Domain", "WriteDacl"),
            # 13. Owns to USER
            ("Owns", "User", "SetOwner"),
            # 14. Owns to GROUP
            ("Owns", "Group", "SetOwner"),
            # 15. Owns to DOMAIN
            ("Owns", "Domain", "SetOwner"),
            # 16. WriteOwner to USER
            ("WriteOwner", "User", "WriteOwner"),
            # 17. WriteOwner to GROUP
            ("WriteOwner", "Group", "WriteOwner"),
            # 18. WriteOwner to DOMAIN
            ("WriteOwner", "Domain", "WriteOwner"),
            # 19. ForceChangePassword to USER
            ("ForceChangePassword", "User", "00299570-246d-11d0-a768-00aa006e0529"),
        ]

        self.assertEqual(len(test_cases), 19)

        for rel, tgt_type, expected_keyword in test_cases:
            snippet = self.builder.get_remediation_block(
                rel_type=rel,
                source="SRC_USER@INLANEFREIGHT.LOCAL",
                target="TGT_OBJECT@INLANEFREIGHT.LOCAL",
                target_type=tgt_type,
            )
            self.assertIn(
                expected_keyword,
                snippet,
                f"Failed for ({rel} -> {tgt_type}): Expected '{expected_keyword}' in snippet"
            )
            self.assertNotIn("SKIPPED: Unrecognized", snippet)

    def test_unrecognized_edge_handling(self):
        """Verify invalid or unhandled edges produce a clean skip notification."""
        snippet = self.builder.get_remediation_block(
            rel_type="InvalidRelationship",
            source="USERA",
            target="USERB",
            target_type="User",
        )
        self.assertIn("SKIPPED: Unrecognized edge condition", snippet)


class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.engine = RemediationEngine(output_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_engine_generate_script(self):
        targets = [
            {
                "type": "GenericAll",
                "source": "WLEY@INLANEFREIGHT.LOCAL",
                "target": "ENGINEERING@INLANEFREIGHT.LOCAL",
                "target_type": "Group",
                "index": 0,
            },
            {
                "type": "DCSync",
                "source": "ENGINEERING",
                "target": "INLANEFREIGHT.LOCAL",
                "target_type": "Domain",
                "index": 1,
            },
        ]

        result = self.engine.generate_script(
            remediation_targets=targets,
            project_name="Unit Test Assessment",
            domain="INLANEFREIGHT.LOCAL",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["target_count"], 2)
        self.assertTrue(os.path.exists(result["output_path"]))
        self.assertGreater(result["file_size"], 100)

        # Inspect generated script content
        content = result["script_content"]
        self.assertIn("Unit Test Assessment", content)
        self.assertIn("INLANEFREIGHT.LOCAL", content)
        self.assertIn("Import-Module ActiveDirectory", content)
        self.assertIn("GenericAll", content)
        self.assertIn("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", content)


class TestProjectManagerRemediation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pm = ProjectManager(projects_dir=self.temp_dir.name)
        self.test_proj_id = f"proj_test_{uuid.uuid4().hex[:8]}"
        self.pm.register_project(self.test_proj_id, name="Test Remediation Proj")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_add_and_retrieve_remediation_scripts(self):
        script_record = {
            "id": "rem_1",
            "filename": "remediation_plan_20260819_120000.ps1",
            "created_at": "2026-08-19 12:00:00",
            "relative_path": "data/projects/test/scripts/remediation_plan_20260819_120000.ps1",
            "file_size": 2048,
            "target_count": 3,
            "included_edges": [{"type": "GenericAll", "source": "A", "target": "B"}],
            "excluded_edges": [],
        }

        self.pm.add_remediation_script(self.test_proj_id, script_record)

        scripts = self.pm.get_remediation_scripts(self.test_proj_id)
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0]["id"], "rem_1")
        self.assertEqual(scripts[0]["target_count"], 3)

        # Test find by ID
        found = self.pm.get_remediation_script_by_id(self.test_proj_id, "rem_1")
        self.assertIsNotNone(found)
        self.assertEqual(found["filename"], "remediation_plan_20260819_120000.ps1")


class TestRemediationWebAPI(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        self.pm = ProjectManager()
        self.test_name = f"Remediation Test {uuid.uuid4().hex[:6]}"
        res = self.client.post("/api/projects/create", json={"name": self.test_name})
        self.project_id = res.json()["project"]["project_id"]
        self.client.post("/api/projects/select", json={"project_id": self.project_id})

    def tearDown(self):
        self.pm.delete_project(self.project_id)

    def test_generate_and_download_remediation_api(self):
        payload = {
            "targets": [
                {
                    "index": 0,
                    "source": "WLEY@INLANEFREIGHT.LOCAL",
                    "type": "GenericAll",
                    "target": "ENGINEERING@INLANEFREIGHT.LOCAL",
                    "target_type": "Group",
                },
                {
                    "index": 1,
                    "source": "ENGINEERING",
                    "type": "MemberOf",
                    "target": "DEV_ADMINS",
                    "target_type": "Group",
                },
            ],
            "all_edges": [
                {
                    "index": 0,
                    "source": "WLEY@INLANEFREIGHT.LOCAL",
                    "type": "GenericAll",
                    "target": "ENGINEERING@INLANEFREIGHT.LOCAL",
                    "target_type": "Group",
                },
                {
                    "index": 1,
                    "source": "ENGINEERING",
                    "type": "MemberOf",
                    "target": "DEV_ADMINS",
                    "target_type": "Group",
                },
                {
                    "index": 2,
                    "source": "DEV_ADMINS",
                    "type": "WriteDacl",
                    "target": "DC01",
                    "target_type": "Domain",
                },
            ],
            "path_summary": {
                "source": "WLEY@INLANEFREIGHT.LOCAL",
                "target": "DC01",
                "engine": "tactical",
            },
            "project_id": self.project_id,
        }

        # 1. POST /api/remediation/generate
        gen_res = self.client.post("/api/remediation/generate", json=payload)
        self.assertEqual(gen_res.status_code, 200)
        data = gen_res.json()
        self.assertEqual(data["status"], "ok")
        script = data["script"]
        self.assertEqual(script["target_count"], 2)
        self.assertEqual(len(script["included_edges"]), 2)
        self.assertEqual(len(script["excluded_edges"]), 1)
        script_id = script["id"]

        # 2. GET /api/remediation/scripts
        list_res = self.client.get(f"/api/remediation/scripts?project_id={self.project_id}")
        self.assertEqual(list_res.status_code, 200)
        scripts = list_res.json()["scripts"]
        self.assertGreaterEqual(len(scripts), 1)
        self.assertEqual(scripts[0]["id"], script_id)

        # 3. GET /api/remediation/scripts/{script_id}
        get_res = self.client.get(f"/api/remediation/scripts/{script_id}?project_id={self.project_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["script"]["id"], script_id)
        self.assertIn("GenericAll", get_res.json()["script"]["script_content"])

        # 4. GET /api/remediation/scripts/{script_id}/download
        down_res = self.client.get(f"/api/remediation/scripts/{script_id}/download?project_id={self.project_id}")
        self.assertEqual(down_res.status_code, 200)
        self.assertIn("text/plain", down_res.headers["content-type"])
        self.assertIn(".ps1", down_res.headers.get("content-disposition", ""))
        self.assertIn("Starting ViperACL Remediation Protocol", down_res.text)


if __name__ == "__main__":
    unittest.main()
