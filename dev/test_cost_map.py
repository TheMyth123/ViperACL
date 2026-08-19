# dev/test_cost_map.py
import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.pathfinder.tactical import COST_MAP, calculate_path_weight, get_edge_cost
from core.pathfinder.predictive import extract_features, FEATURE_COLUMNS, REL_TYPES


class TestTacticalCostMap(unittest.TestCase):
    def test_cost_map_values(self):
        """Verify all entries in COST_MAP match specifications exactly."""
        expected = {
            ('MemberOf', 'GROUP'): 0,
            ('DCSync', 'DOMAIN'): 0,
            ('AddMember', 'GROUP'): 1,
            ('GenericWrite', 'GROUP'): 1,
            ('GenericAll', 'USER'): 3,
            ('GenericAll', 'GROUP'): 1,
            ('GenericAll', 'DOMAIN'): 0,
            ('AllExtendedRights', 'USER'): 3,
            ('AllExtendedRights', 'DOMAIN'): 0,
            ('WriteDacl', 'USER'): 4,
            ('WriteDacl', 'GROUP'): 2,
            ('WriteDacl', 'DOMAIN'): 1,
            ('Owns', 'USER'): 4,
            ('Owns', 'GROUP'): 2,
            ('Owns', 'DOMAIN'): 1,
            ('WriteOwner', 'USER'): 5,
            ('WriteOwner', 'GROUP'): 3,
            ('WriteOwner', 'DOMAIN'): 2,
            ('ForceChangePassword', 'USER'): 5,
        }
        self.assertEqual(COST_MAP, expected)

    def test_get_edge_cost_by_target(self):
        """Verify get_edge_cost returns correct weights based on target node class."""
        # GenericAll differences
        user_node = {"name": "ALICE@CORP.LOCAL", "labels": ["Base", "User"]}
        group_node = {"name": "IT_ADMINS@CORP.LOCAL", "labels": ["Base", "Group"]}
        domain_node = {"name": "CORP.LOCAL", "labels": ["Base", "Domain"]}

        self.assertEqual(get_edge_cost("GenericAll", user_node), 3)
        self.assertEqual(get_edge_cost("GenericAll", group_node), 1)
        self.assertEqual(get_edge_cost("GenericAll", domain_node), 0)

        # WriteDacl differences
        self.assertEqual(get_edge_cost("WriteDacl", user_node), 4)
        self.assertEqual(get_edge_cost("WriteDacl", group_node), 2)
        self.assertEqual(get_edge_cost("WriteDacl", domain_node), 1)

        # Owns differences
        self.assertEqual(get_edge_cost("Owns", user_node), 4)
        self.assertEqual(get_edge_cost("Owns", group_node), 2)
        self.assertEqual(get_edge_cost("Owns", domain_node), 1)

        # WriteOwner differences
        self.assertEqual(get_edge_cost("WriteOwner", user_node), 5)
        self.assertEqual(get_edge_cost("WriteOwner", group_node), 3)
        self.assertEqual(get_edge_cost("WriteOwner", domain_node), 2)

        # AllExtendedRights differences
        self.assertEqual(get_edge_cost("AllExtendedRights", user_node), 3)
        self.assertEqual(get_edge_cost("AllExtendedRights", domain_node), 0)

        # Passive
        self.assertEqual(get_edge_cost("MemberOf", group_node), 0)
        self.assertEqual(get_edge_cost("DCSync", domain_node), 0)

        # Direct group modification
        self.assertEqual(get_edge_cost("AddMember", group_node), 1)
        self.assertEqual(get_edge_cost("GenericWrite", group_node), 1)

        # Password reset
        self.assertEqual(get_edge_cost("ForceChangePassword", user_node), 5)

        # Fallback for undefined
        unknown_node = {"name": "UNKNOWN", "labels": ["Unknown"]}
        self.assertEqual(get_edge_cost("UnknownRel", unknown_node), 10)

    def test_calculate_path_weight(self):
        """Verify total path weight is calculated summing target-aware edge weights."""
        # Path: User1 -[MemberOf]-> GroupA -[GenericAll]-> User2 -[WriteDacl]-> Domain
        # MemberOf -> Group: 0
        # GenericAll -> User: 3
        # WriteDacl -> Domain: 1
        # Total: 0 + 3 + 1 = 4
        path = [
            {"name": "USER_1", "labels": ["Base", "User"]},
            "MemberOf",
            {"name": "GROUP_A", "labels": ["Base", "Group"]},
            "GenericAll",
            {"name": "USER_2", "labels": ["Base", "User"]},
            "WriteDacl",
            {"name": "DOMAIN_ROOT", "labels": ["Base", "Domain"]},
        ]
        self.assertEqual(calculate_path_weight(path), 4)

        # Compare with Path: User1 -[MemberOf]-> GroupA -[GenericAll]-> GroupB -[WriteDacl]-> Domain
        # MemberOf -> Group: 0
        # GenericAll -> Group: 1
        # WriteDacl -> Domain: 1
        # Total: 0 + 1 + 1 = 2
        path2 = [
            {"name": "USER_1", "labels": ["Base", "User"]},
            "MemberOf",
            {"name": "GROUP_A", "labels": ["Base", "Group"]},
            "GenericAll",
            {"name": "GROUP_B", "labels": ["Base", "Group"]},
            "WriteDacl",
            {"name": "DOMAIN_ROOT", "labels": ["Base", "Domain"]},
        ]
        self.assertEqual(calculate_path_weight(path2), 2)

    def test_predictive_feature_extraction(self):
        """Verify ML feature extraction uses target-aware costs for TotalCost and MaxCost."""
        path = [
            {"name": "USER_1", "labels": ["Base", "User"]},
            "MemberOf",
            {"name": "GROUP_A", "labels": ["Base", "Group"]},
            "GenericAll",
            {"name": "USER_2", "labels": ["Base", "User"]},
            "WriteOwner",
            {"name": "USER_3", "labels": ["Base", "User"]},
        ]
        # Hops: 3
        # MemberOf -> Group: 0
        # GenericAll -> User: 3
        # WriteOwner -> User: 5
        # TotalCost: 8, MaxCost: 5
        feats = extract_features(path)
        self.assertEqual(feats[0], 3)  # Hops
        self.assertEqual(feats[1], 8)  # TotalCost
        self.assertEqual(feats[2], 5)  # MaxCost


if __name__ == "__main__":
    unittest.main()
