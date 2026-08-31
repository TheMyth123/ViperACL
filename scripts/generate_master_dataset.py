"""
scripts/generate_master_dataset.py
Unified Master AD Attack Path Telemetry Dataset Generator for ViperACL.

Acts as the Single Source of Truth for all 3 machine learning models:
1. Generates canonical, sequence-rich Active Directory attack paths.
2. Applies realistic, calibrated ground-truth success probabilities:
   - Clean DACL / Stealth Takeovers        : ~98% Feasibility
   - Clean Passive Group Traversal          : ~95% Feasibility
   - FastTrack Password Reset Chains        : ~70% Feasibility (EDR noise risk, high direct speed)
   - Kerberos Token Sync Paradox (AM->GA)   : ~45% Feasibility (penalized for ticket lag, but feasible)
   - PAC Token Bloat Paradox (3+ AM)        : ~40% Feasibility
   - Credential Race (Reset -> AM)          : ~35% Feasibility
   - Excessive EDR Lockout Alarm (3+ Resets): ~25% Feasibility
   - Deep Multi-Hop Tactical Friction (6+ H): ~30% Feasibility
3. Exports:
   - Canonical Master JSONL: data/master_synthetic_{training,testing}.jsonl
   - Path-Transformer JSONL: data/transformer_synthetic_{training,testing}.jsonl
   - Random Forest CSVs    : data/rf_synthetic_{training,testing}.csv & data/synthetic_{training,testing}.csv
   - LightGBM CSVs         : data/lgbm_synthetic_{training,testing}.csv
"""

from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.pathfinder.lgbm_predictive import LGBM_FEATURE_COLUMNS, extract_lgbm_features
from core.pathfinder.rf_predictive import RF_FEATURE_COLUMNS, extract_rf_features
from core.pathfinder.tactical import COST_MAP

NODE_TYPES = ["USER", "GROUP", "COMPUTER", "DOMAIN"]


def sample_node_name(node_type: str, prefix: str = "") -> str:
    rnd = random.randint(1000, 9999)
    if node_type == "USER":
        return f"{prefix}USER_{rnd}@CORP.LOCAL"
    if node_type == "GROUP":
        return f"{prefix}GROUP_{rnd}@CORP.LOCAL"
    if node_type == "COMPUTER":
        return f"{prefix}SRV_{rnd}.CORP.LOCAL"
    return "CORP.LOCAL"


def create_hop(s_type: str, s_name: str, rel: str, t_type: str, t_name: str) -> dict:
    cost = COST_MAP.get((rel, t_type), 2)
    is_passive = 1.0 if rel in ("MemberOf", "DCSync", "GetChanges", "GetChangesAll") else 0.0
    return {
        "source_type": s_type,
        "source_name": s_name,
        "relationship": rel,
        "target_type": t_type,
        "target_name": t_name,
        "cost": cost,
        "is_passive": is_passive,
    }


def generate_clean_passive_path() -> tuple[list[dict], float]:
    """Passive group traversal ending in DCSync."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")
    num_hops = random.randint(1, 3)
    for _ in range(num_hops):
        next_type, next_name = "GROUP", sample_node_name("GROUP")
        hops.append(create_hop(curr_type, curr_name, "MemberOf", next_type, next_name))
        curr_type, curr_name = next_type, next_name
    hops.append(create_hop(curr_type, curr_name, "DCSync", "DOMAIN", "CORP.LOCAL"))
    return hops, 0.95


def generate_clean_dacl_path() -> tuple[list[dict], float]:
    """Stealth DACL ownership / takeover chain."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("MemberOf", "GROUP"), ("Owns", "GROUP"), ("WriteOwner", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("MemberOf", "GROUP"), ("Owns", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("MemberOf", "GROUP"), ("WriteOwner", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("MemberOf", "GROUP"), ("MemberOf", "GROUP"), ("Owns", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("GenericWrite", "GROUP"), ("WriteOwner", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("Owns", "GROUP"), ("WriteDacl", "GROUP"), ("AllExtendedRights", "DOMAIN")],
        [("MemberOf", "GROUP"), ("Owns", "GROUP"), ("GenericAll", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.98


def generate_fasttrack_reset_path() -> tuple[list[dict], float]:
    """Password reset fast-track chains."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")],
        [("MemberOf", "GROUP"), ("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("MemberOf", "GROUP"), ("AllExtendedRights", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("GenericWrite", "GROUP"), ("WriteDacl", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.70


def generate_paradox_am_exploit_path() -> tuple[list[dict], float]:
    """Kerberos Token Refresh Paradox (AddMember -> Immediate Exploit)."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("MemberOf", "GROUP"), ("AddMember", "GROUP"), ("GenericAll", "GROUP"), ("AllExtendedRights", "DOMAIN")],
        [("AddMember", "GROUP"), ("GenericAll", "USER"), ("GenericAll", "DOMAIN")],
        [("MemberOf", "GROUP"), ("AddMember", "GROUP"), ("GenericAll", "USER"), ("DCSync", "DOMAIN")],
        [("AddMember", "GROUP"), ("GenericWrite", "GROUP"), ("GenericAll", "DOMAIN")],
        [("AddMember", "GROUP"), ("AllExtendedRights", "USER"), ("GenericAll", "DOMAIN")],
        [("AddMember", "GROUP"), ("WriteDacl", "GROUP"), ("GenericAll", "DOMAIN")],
        [("AddMember", "GROUP"), ("GenericAll", "GROUP"), ("WriteDacl", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.45


def generate_paradox_pac_bloat_path() -> tuple[list[dict], float]:
    """Kerberos PAC Token Bloat Paradox (Multiple consecutive AddMember)."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("AddMember", "GROUP"), ("AddMember", "GROUP"), ("AddMember", "GROUP"), ("GenericAll", "DOMAIN")],
        [("MemberOf", "GROUP"), ("AddMember", "GROUP"), ("AddMember", "GROUP"), ("AddMember", "GROUP"), ("AllExtendedRights", "DOMAIN")],
        [("AddMember", "GROUP"), ("AddMember", "GROUP"), ("AddMember", "GROUP"), ("AddMember", "GROUP"), ("DCSync", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.40


def generate_paradox_race_path() -> tuple[list[dict], float]:
    """Credential Propagation Race Paradox (ForceChangePassword -> AddMember)."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("ForceChangePassword", "USER"), ("AddMember", "GROUP"), ("GenericAll", "DOMAIN")],
        [("MemberOf", "GROUP"), ("ForceChangePassword", "USER"), ("AddMember", "GROUP"), ("WriteDacl", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("AddMember", "GROUP"), ("GenericWrite", "GROUP"), ("AllExtendedRights", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.35


def generate_paradox_edr_lockout_path() -> tuple[list[dict], float]:
    """Excessive EDR Lockout Alarm (3+ chained password resets)."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("DCSync", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.25


def generate_high_friction_loop_path() -> tuple[list[dict], float]:
    """Deep Multi-Hop Tactical Friction (6+ hops with multiple active modifications)."""
    hops = []
    curr_type, curr_name = "USER", sample_node_name("USER", "SRC_")

    patterns = [
        [("GenericWrite", "USER"), ("GenericWrite", "USER"), ("WriteOwner", "GROUP"), ("WriteDacl", "GROUP"), ("GenericAll", "USER"), ("AllExtendedRights", "DOMAIN")],
        [("WriteOwner", "USER"), ("WriteDacl", "USER"), ("ForceChangePassword", "USER"), ("GenericWrite", "GROUP"), ("WriteDacl", "GROUP"), ("GenericAll", "DOMAIN")],
        [("ForceChangePassword", "USER"), ("GenericWrite", "USER"), ("ForceChangePassword", "USER"), ("WriteOwner", "GROUP"), ("WriteDacl", "DOMAIN")],
    ]
    pattern = random.choice(patterns)
    for rel, t_type in pattern:
        t_name = "CORP.LOCAL" if t_type == "DOMAIN" else sample_node_name(t_type)
        hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
        curr_type, curr_name = t_type, t_name

    return hops, 0.30


def hops_to_traversal_path(hops: list[dict]) -> list:
    """Converts a sequence of hop dicts into alternating [node, rel, node, rel, ...] list for feature extractors."""
    if not hops:
        return []
    path = [{"name": hops[0]["source_name"], "labels": [hops[0]["source_type"]]}]
    for h in hops:
        path.append(h["relationship"])
        path.append({"name": h["target_name"], "labels": [h["target_type"]]})
    return path


def generate_master_dataset(num_samples: int = 2400, seed: int = 42) -> list[dict]:
    """Generates canonical master dataset samples with grounded target probabilities."""
    random.seed(seed)

    archetypes = [
        ("CLEAN_DACL", generate_clean_dacl_path, 0.28),
        ("CLEAN_PASSIVE", generate_clean_passive_path, 0.20),
        ("FASTTRACK_RESET", generate_fasttrack_reset_path, 0.18),
        ("PARADOX_AM_EXPLOIT", generate_paradox_am_exploit_path, 0.14),
        ("PARADOX_PAC_BLOAT", generate_paradox_pac_bloat_path, 0.06),
        ("PARADOX_RACE", generate_paradox_race_path, 0.05),
        ("PARADOX_EDR_LOCKOUT", generate_paradox_edr_lockout_path, 0.04),
        ("HIGH_FRICTION_LOOP", generate_high_friction_loop_path, 0.05),
    ]

    categories, generators, weights = zip(*archetypes)
    samples = []

    # Explicit anchor samples to guarantee anchor archetype presence in both train & test
    anchor_archetypes = [
        ("CLEAN_DACL", [("MemberOf", "GROUP"), ("Owns", "GROUP"), ("WriteOwner", "GROUP"), ("WriteDacl", "DOMAIN")], 0.98, 200),
        ("FASTTRACK_RESET", [("ForceChangePassword", "USER"), ("ForceChangePassword", "USER"), ("GenericAll", "DOMAIN")], 0.70, 180),
        ("PARADOX_AM_EXPLOIT", [("MemberOf", "GROUP"), ("AddMember", "GROUP"), ("GenericAll", "GROUP"), ("AllExtendedRights", "DOMAIN")], 0.45, 180),
    ]

    for cat_name, pattern, prob, count in anchor_archetypes:
        for idx in range(count):
            hops = []
            curr_type, curr_name = "USER", f"ANCHOR_SRC_{idx}@CORP.LOCAL"
            for rel, t_type in pattern:
                t_name = "CORP.LOCAL" if t_type == "DOMAIN" else f"ANCHOR_{t_type}_{idx}@CORP.LOCAL"
                hops.append(create_hop(curr_type, curr_name, rel, t_type, t_name))
                curr_type, curr_name = t_type, t_name

            lbl = 1 if (idx / count) < prob else 0
            samples.append({
                "sample_id": f"anchor_{cat_name.lower()}_{idx:04d}",
                "category": cat_name,
                "target_prob": prob,
                "success": lbl,
                "hops": hops,
            })

    # Diverse random generation
    remaining_count = num_samples - len(samples)
    for idx in range(remaining_count):
        cat = random.choices(categories, weights=weights)[0]
        gen_fn = generators[categories.index(cat)]
        hops, prob = gen_fn()
        lbl = 1 if random.random() < prob else 0

        samples.append({
            "sample_id": f"sample_{cat.lower()}_{idx:05d}",
            "category": cat,
            "target_prob": prob,
            "success": lbl,
            "hops": hops,
        })

    random.shuffle(samples)
    return samples


def export_datasets(samples: list[dict], train_ratio: float = 0.8):
    """Exports canonical master, tabular CSV, and sequence JSONL datasets."""
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    split_idx = int(len(samples) * train_ratio)
    train_samples = samples[:split_idx]
    test_samples = samples[split_idx:]

    print(f"[*] Total master dataset: {len(samples)} samples ({len(train_samples)} train / {len(test_samples)} test)")
    print(f"    Train class balance: Success=1: {sum(s['success'] == 1 for s in train_samples)} ({sum(s['success'] == 1 for s in train_samples)/len(train_samples):.1%}), "
          f"Success=0: {sum(s['success'] == 0 for s in train_samples)} ({sum(s['success'] == 0 for s in train_samples)/len(train_samples):.1%})")

    # 1. Export Master JSONL
    for name, split in [("training", train_samples), ("testing", test_samples)]:
        master_path = data_dir / f"master_synthetic_{name}.jsonl"
        with open(master_path, "w", encoding="utf-8") as f:
            for s in split:
                f.write(json.dumps(s) + "\n")

    # 2. Export Path-Transformer JSONL
    for name, split in [("training", train_samples), ("testing", test_samples)]:
        trans_path = data_dir / f"transformer_synthetic_{name}.jsonl"
        with open(trans_path, "w", encoding="utf-8") as f:
            for s in split:
                f.write(json.dumps({
                    "sample_id": s["sample_id"],
                    "category": s["category"],
                    "success": s["success"],
                    "hops": s["hops"],
                }) + "\n")

    # 3. Export Tabular CSVs for Random Forest & LightGBM
    for name, split in [("training", train_samples), ("testing", test_samples)]:
        rf_rows = []
        lgbm_rows = []

        for s in split:
            path_repr = hops_to_traversal_path(s["hops"])
            rf_feats = extract_rf_features(path_repr)
            lgbm_feats = extract_lgbm_features(path_repr)
            rf_rows.append(rf_feats + [s["success"]])
            lgbm_rows.append(lgbm_feats + [s["success"]])

        # Random Forest CSVs
        for rf_filename in (f"rf_synthetic_{name}.csv", f"synthetic_{name}.csv"):
            with open(data_dir / rf_filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(RF_FEATURE_COLUMNS + ["Success"])
                writer.writerows(rf_rows)

        # LightGBM CSVs
        with open(data_dir / f"lgbm_synthetic_{name}.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(LGBM_FEATURE_COLUMNS + ["Success"])
            writer.writerows(lgbm_rows)

    print("[+] Successfully exported all master, tabular, and sequence dataset files.")


def main():
    print("=" * 75)
    print("    VIPERACL PREDICTIVE ENGINE — UNIFIED MASTER DATASET GENERATION")
    print("=" * 75)
    samples = generate_master_dataset(num_samples=2400, seed=42)
    export_datasets(samples, train_ratio=0.8)


if __name__ == "__main__":
    main()
