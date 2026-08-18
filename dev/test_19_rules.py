"""
Comprehensive validation test suite for:
1. Universal Accepted Edges (all 19 accepted relationship -> target types across all hops).
2. Rejection of invalid edges in start, intermediate, or end positions.
3. DCSync synthesis and path merging (GetChanges + GetChangesAll -> DCSync).
"""

import os
import sys
import unittest

# Root folder search path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.pathfinder.rules import (
    ACCEPTED_EDGES,
    get_node_type,
    is_valid_edge,
    is_valid_path,
    normalize_path_dcsync,
    get_path_signature,
)


class TestPathfinderAcceptedEdges(unittest.TestCase):
    def test_accepted_19_edges_count(self):
        """Verify exactly 19 unique accepted edges are defined."""
        self.assertEqual(len(ACCEPTED_EDGES), 19)

    def test_all_19_edges_valid(self):
        """Verify each of the 19 accepted edges is recognized as valid individually."""
        for rel, target_type in ACCEPTED_EDGES:
            target_node = {"name": f"TARGET_{target_type.upper()}", "labels": ["Base", target_type]}
            self.assertTrue(
                is_valid_edge(rel, target_node),
                f"Edge ({rel} -> {target_type}) should be recognized as an ACCEPTED edge."
            )

    def test_invalid_edges_rejected(self):
        """Verify invalid edges are strictly rejected."""
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
            target_node = {"name": f"TARGET_{target_type.upper()}", "labels": ["Base", target_type]}
            self.assertFalse(
                is_valid_edge(rel, target_node),
                f"Edge ({rel} -> {target_type}) must be strictly REJECTED."
            )

    def test_multi_hop_path_all_valid(self):
        """Verify a multi-hop path where all edges are accepted is valid."""
        valid_chain = [
            {"name": "USER_1", "labels": ["Base", "User"]},
            "MemberOf",
            {"name": "GROUP_A", "labels": ["Base", "Group"]},
            "AddMember",
            {"name": "GROUP_B", "labels": ["Base", "Group"]},
            "GenericAll",
            {"name": "USER_2", "labels": ["Base", "User"]},
            "ForceChangePassword",
            {"name": "USER_3", "labels": ["Base", "User"]},
        ]
        self.assertTrue(is_valid_path(valid_chain))

    def test_multi_hop_path_intermediate_invalid_rejected(self):
        """Verify a path with an invalid intermediate edge (e.g. GenericWrite -> User) is rejected."""
        invalid_intermediate_chain = [
            {"name": "USER_1", "labels": ["Base", "User"]},
            "GenericWrite",  # INVALID to User!
            {"name": "USER_2", "labels": ["Base", "User"]},
            "WriteDacl",
            {"name": "USER_3", "labels": ["Base", "User"]},
        ]
        self.assertFalse(is_valid_path(invalid_intermediate_chain))

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
                src = params.get("src_name", "") or params.get("src_id", "")
                tgt = params.get("tgt_name", "") or params.get("tgt_id", "")
                if "TESTUSER6" in src and "VIPERTECH" in tgt:
                    return [{"has_gc": True, "has_gca": True}]
                if "NO_DCSYNC" in src:
                    return [{"has_gc": True, "has_gca": False}]
                return [{"has_gc": False, "has_gca": False}]

        mock_db = MockDB()

        # Path 1: GetChanges
        path1 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "WriteDacl",
            {"name": "TESTUSER6@VIPERTECH.LOCAL", "labels": ["Base", "User"]},
            "GetChanges",
            {"name": "VIPERTECH.LOCAL", "labels": ["Base", "Domain"]},
        ]

        # Path 2: GetChangesAll
        path2 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "WriteDacl",
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
        self.assertTrue(is_valid_path(norm1))

        # Path 3: User with only GetChanges (cannot DCSync)
        path3 = [
            {"name": "TEST", "labels": ["Base", "User"]},
            "WriteDacl",
            {"name": "NO_DCSYNC_USER@VIPERTECH.LOCAL", "labels": ["Base", "User"]},
            "GetChanges",
            {"name": "VIPERTECH.LOCAL", "labels": ["Base", "Domain"]},
        ]
        norm3 = normalize_path_dcsync(path3, mock_db)
        self.assertEqual(norm3[3], "GetChanges")  # Remains GetChanges
        self.assertFalse(is_valid_path(norm3))  # Rejected because GetChanges is not in ACCEPTED_EDGES


if __name__ == "__main__":
    unittest.main()
