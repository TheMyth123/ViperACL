"""
Comprehensive validation test suite for:
1. DCSync synthesis and path merging (GetChanges + GetChangesAll -> DCSync).
2. The 19 strict path end conditions.
"""

import os
import sys
import unittest
from types import SimpleNamespace

# Root folder search path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.pathfinder.rules import (
    ALLOWED_END_CONDITIONS,
    get_node_type,
    is_valid_end_condition,
    normalize_path_dcsync,
    get_path_signature,
)
from core.database import DatabaseManager
from core.pathfinder.pathfinder import PathfinderCoordinator


class TestPathfinderRules(unittest.TestCase):
    def test_allowed_19_conditions_count(self):
        """Verify exactly 19 unique conditions are defined."""
        self.assertEqual(len(ALLOWED_END_CONDITIONS), 19)

    def test_all_19_conditions_valid(self):
        """Verify each of the 19 conditions is recognized as valid."""
        for rel, target_type in ALLOWED_END_CONDITIONS:
            dummy_path = [
                {"name": "SOURCE_USER", "labels": ["Base", "User"]},
                rel,
                {"name": f"TARGET_{target_type.upper()}", "labels": ["Base", target_type]},
            ]
            self.assertTrue(
                is_valid_end_condition(dummy_path),
                f"Condition ({rel} -> {target_type}) should be recognized as VALID."
            )

    def test_invalid_conditions_rejected(self):
        """Verify invalid conditions are strictly rejected."""
        invalid_pairs = [
            ("GenericWrite", "User"),
            ("GenericWrite", "Domain"),
            ("ForceChangePassword", "Group"),
            ("ForceChangePassword", "Domain"),
            ("AllExtendedRights", "Group"),
            ("MemberOf", "User"),
            ("MemberOf", "Domain"),
            ("AddMember", "User"),
            ("AddMember", "Domain"),
            ("DCSync", "User"),
            ("DCSync", "Group"),
            ("GetChanges", "Domain"),
            ("GetChangesAll", "Domain"),
            ("GetChanges", "User"),
            ("GetChangesAll", "Group"),
            ("GenericAll", "Computer"),
            ("GenericWrite", "Computer"),
            ("WriteDacl", "Computer"),
            ("WriteOwner", "Computer"),
            ("Owns", "Computer"),
            ("ForceChangePassword", "Computer"),
        ]

        for rel, target_type in invalid_pairs:
            dummy_path = [
                {"name": "SOURCE_USER", "labels": ["Base", "User"]},
                rel,
                {"name": f"TARGET_{target_type.upper()}", "labels": ["Base", target_type]},
            ]
            self.assertFalse(
                is_valid_end_condition(dummy_path),
                f"Condition ({rel} -> {target_type}) must be strictly REJECTED."
            )

    def test_get_node_type(self):
        """Verify correct AD class extraction from various node structures."""
        self.assertEqual(get_node_type({"labels": ["Base", "User"]}), "User")
        self.assertEqual(get_node_type({"labels": ["Base", "Group"]}), "Group")
        self.assertEqual(get_node_type({"labels": ["Base", "Domain"]}), "Domain")
        self.assertEqual(get_node_type({"labels": ["Base", "Computer"]}), "Computer")
        self.assertEqual(get_node_type({"labels": ["Base", "GPO"]}), "GPO")
        self.assertEqual(get_node_type({"labels": ["Base", "OU"]}), "OU")
        self.assertEqual(get_node_type({"labels": ["Base", "Container"]}), "Container")

    def test_dcsync_normalization_and_merging(self):
        """Verify DCSync synthesis and deduplication logic."""
        class MockDB:
            def run_query(self, query, params=None):
                # Simulate TESTUSER6 having both GetChanges and GetChangesAll to VIPERTECH.LOCAL
                src = params.get("src_name", "") or params.get("src_id", "")
                tgt = params.get("tgt_name", "") or params.get("tgt_id", "")
                if "TESTUSER6" in src and "VIPERTECH" in tgt:
                    return [{"has_gc": True, "has_gca": True}]
                # Simulate NO_DCSYNC_USER having only GetChanges
                if "NO_DCSYNC" in src:
                    return [{"has_gc": True, "has_gca": False}]
                return [{"has_gc": False, "has_gca": False}]

        mock_db = MockDB()

        # Path 1: GetChanges
        path1 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "AddMember",
            {"name": "TESTUSER6@VIPERTECH.LOCAL", "labels": ["Base", "User"]},
            "GetChanges",
            {"name": "VIPERTECH.LOCAL", "labels": ["Base", "Domain"]},
        ]

        # Path 2: GetChangesAll
        path2 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "AddMember",
            {"name": "TESTUSER6@VIPERTECH.LOCAL", "labels": ["Base", "User"]},
            "GetChangesAll",
            {"name": "VIPERTECH.LOCAL", "labels": ["Base", "Domain"]},
        ]

        norm1 = normalize_path_dcsync(path1, mock_db)
        norm2 = normalize_path_dcsync(path2, mock_db)

        self.assertEqual(norm1[3], "DCSync")
        self.assertEqual(norm2[3], "DCSync")

        # Verify they produce the exact same signature (merging into 1 path)
        sig1 = get_path_signature(norm1)
        sig2 = get_path_signature(norm2)
        self.assertEqual(sig1, sig2)
        self.assertTrue(is_valid_end_condition(norm1))

        # Path 3: User with only GetChanges (cannot DCSync)
        path3 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "AddMember",
            {"name": "NO_DCSYNC_USER@VIPERTECH.LOCAL", "labels": ["Base", "User"]},
            "GetChanges",
            {"name": "VIPERTECH.LOCAL", "labels": ["Base", "Domain"]},
        ]
        norm3 = normalize_path_dcsync(path3, mock_db)
        self.assertEqual(norm3[3], "GetChanges")  # Remains GetChanges
        self.assertFalse(is_valid_end_condition(norm3))  # Rejected by 19 rules!


if __name__ == "__main__":
    unittest.main()
