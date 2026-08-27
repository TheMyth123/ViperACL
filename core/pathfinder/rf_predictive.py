"""
core/pathfinder/rf_predictive.py
Random Forest Predictive Pathfinder Engine for ViperACL.
Extracts 27-D tabular telemetry features from candidate Active Directory graph attack paths,
scores path operational feasibility using serialized Balanced Random Forest ensemble weights,
and ranks candidates.
"""

from __future__ import annotations

import pandas as pd

from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)
from .tactical import COST_MAP, get_edge_cost

# Dynamically sort relationships alphabetically to ensure consistent column order
RF_REL_TYPES = sorted(list({k[0] for k in COST_MAP.keys()} | {"GetChanges", "GetChangesAll"}))
RF_FEATURE_COLUMNS = (
    ["Hops", "TotalCost", "MaxCost"]
    + [f"Count_{rel}" for rel in RF_REL_TYPES]
    + [
        "Has_AddMember_GenericAll",
        "Has_AddMember_Exploit",
        "Consecutive_AddMember",
        "Consecutive_ForceChangePassword",
        "Has_Double_PasswordReset",
        "Has_PasswordReset_Then_AddMember",
        "Consecutive_DACL_Mods",
        "Count_Passive",
        "Count_Active",
        "Avg_Hop_Cost",
        "DACL_Chain_Length",
        "High_Hop_Friction",
    ]
)

# Backwards compatibility alias
FEATURE_COLUMNS = RF_FEATURE_COLUMNS
REL_TYPES = RF_REL_TYPES


def extract_rf_features(path: list, db=None, project_id: str | None = None) -> list:
    """Translates a Cypher path into Random Forest tabular telemetry features."""
    hops = max(1, (len(path) - 1) // 2)
    total_cost = 0
    max_cost = 0
    rel_counts = {rel: 0 for rel in RF_REL_TYPES}
    edges = []

    for i in range(1, len(path) - 1, 2):
        rel = path[i]
        rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
        target_node = path[i + 1]
        cost = get_edge_cost(rel_type, target_node, db, project_id=project_id)

        total_cost += cost
        if cost > max_cost:
            max_cost = cost

        if rel_type in rel_counts:
            rel_counts[rel_type] += 1

        edges.append(rel_type)

    has_am_ga = 0
    has_am_exploit = 0
    has_pwd_then_am = 0
    max_consec_am = 0
    cur_consec_am = 0
    max_consec_fcp = 0
    cur_consec_fcp = 0
    max_consec_dacl = 0
    cur_consec_dacl = 0
    max_dacl_chain = 0
    cur_dacl_chain = 0
    passive_count = 0
    active_count = 0

    for i, rel_type in enumerate(edges):
        if rel_type in ("MemberOf", "DCSync", "GetChanges", "GetChangesAll"):
            passive_count += 1
        else:
            active_count += 1

        # Paradox 1: AddMember immediately followed by GenericAll or active exploit
        if rel_type == "AddMember" and i + 1 < len(edges):
            next_rel = edges[i + 1]
            if next_rel == "GenericAll":
                has_am_ga = 1
            if next_rel in ("GenericAll", "AllExtendedRights", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"):
                has_am_exploit = 1

        # Paradox 2: Consecutive AddMember operations
        if rel_type == "AddMember":
            cur_consec_am += 1
            if cur_consec_am > max_consec_am:
                max_consec_am = cur_consec_am
        else:
            cur_consec_am = 0

        # Paradox 3: Consecutive password resets
        if rel_type == "ForceChangePassword":
            cur_consec_fcp += 1
            if cur_consec_fcp > max_consec_fcp:
                max_consec_fcp = cur_consec_fcp
            if i + 1 < len(edges) and edges[i + 1] == "AddMember":
                has_pwd_then_am = 1
        else:
            cur_consec_fcp = 0

        # Paradox 4: Consecutive DACL Modifications / Ownership Flips
        if rel_type in ("WriteDacl", "WriteOwner", "Owns"):
            cur_consec_dacl += 1
            if cur_consec_dacl > max_consec_dacl:
                max_consec_dacl = cur_consec_dacl
        else:
            cur_consec_dacl = 0

        # Stealth DACL takeover chain (Owns -> WriteOwner -> WriteDacl)
        if rel_type in ("WriteDacl", "WriteOwner", "Owns"):
            cur_dacl_chain += 1
            if cur_dacl_chain > max_dacl_chain:
                max_dacl_chain = cur_dacl_chain
        else:
            cur_dacl_chain = 0

    has_double_pwd = 1 if rel_counts["ForceChangePassword"] >= 2 else 0
    avg_hop_cost = round(total_cost / max(1, hops), 2)
    high_hop_friction = 1 if (hops >= 6 and active_count >= 3) else 0

    features = [hops, total_cost, max_cost]
    for rel in RF_REL_TYPES:
        features.append(rel_counts[rel])

    features.extend([
        has_am_ga,
        has_am_exploit,
        max_consec_am,
        max_consec_fcp,
        has_double_pwd,
        has_pwd_then_am,
        max_consec_dacl,
        passive_count,
        active_count,
        avg_hop_cost,
        max_dacl_chain,
        high_hop_friction,
    ])

    return features


# Backwards compatibility alias
extract_features = extract_rf_features


def compute_rf_confidence(model, features: list) -> float:
    """
    Computes Random Forest class probability percentage.
    Outputs raw tree ensemble probability capped at 99.0% max.
    """
    df_features = pd.DataFrame([features], columns=RF_FEATURE_COLUMNS)
    raw_prob = float(model.predict_proba(df_features)[0][1])

    return round(min(99.0, raw_prob * 100.0), 1)


# Backwards compatibility alias
compute_path_confidence = compute_rf_confidence


def run_rf_predictive(
    db,
    source_name: str,
    target_name: str,
    model,
    max_hops: int = 15,
    ml_threshold: float = 0.50,
    project_id: str | None = None,
) -> list[dict] | None:
    """
    Random Forest Predictive Engine: Evaluates candidate paths using RF bagged tree probabilities.
    Ensures strictly one-way acyclic attack chains from source to target within the active project graph.
    """
    try:
        if project_id:
            rel_rows = db.run_query("MATCH ()-[r {project_id: $pid}]->() RETURN DISTINCT type(r) AS rel", {"pid": project_id})
        else:
            rel_rows = db.run_query("MATCH ()-[r]->() RETURN DISTINCT type(r) AS rel")
        present_rels = {row.get("rel") for row in rel_rows if row.get("rel")}
    except Exception:
        present_rels = set()

    cost_map_rels = {k[0] for k in COST_MAP.keys()}
    if "DCSync" in cost_map_rels:
        cost_map_rels.update({"GetChanges", "GetChangesAll"})

    allowed_rels = [r for r in cost_map_rels if r in present_rels]
    if not allowed_rels:
        return None

    rel_pattern = "|".join(allowed_rels)
    hops_limit = max(1, min(int(max_hops), 50))
    threshold_pct = (ml_threshold * 100) if ml_threshold <= 1.0 else float(ml_threshold)

    params = {
        "source_name": source_name.upper(),
        "target_name": target_name.upper(),
    }
    if project_id:
        params["pid"] = project_id
        src_node = "(source {name: $source_name, project_id: $pid})"
        tgt_node = "(target {name: $target_name, project_id: $pid})"
        rel_filter = "WHERE ALL(r IN relationships(p) WHERE r.project_id = $pid)"
    else:
        src_node = "(source {name: $source_name})"
        tgt_node = "(target {name: $target_name})"
        rel_filter = ""

    # 1. Retrieve all shortest paths efficiently
    q_shortest = f"""
    MATCH {src_node}, {tgt_node}
    MATCH p = allShortestPaths((source)-[:{rel_pattern}*..{hops_limit}]->(target))
    {rel_filter}
    RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    """
    candidate_records = db.run_query(q_shortest, parameters=params) or []
    min_hops = candidate_records[0].get("hops") if candidate_records else None

    # 2. Gather subsequent hop-length paths to explore varied tactical vectors (up to min_hops + 3)
    if min_hops and min_hops < hops_limit:
        max_search_hop = min(min_hops + 3, hops_limit)
        for h in range(min_hops + 1, max_search_hop + 1):
            if len(candidate_records) >= 50:
                break
            if project_id:
                qh = f"""
                MATCH {src_node}, {tgt_node}
                MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
                WHERE ALL(r IN relationships(p) WHERE r.project_id = $pid)
                AND none(n IN nodes(p)[0..-2] WHERE toUpper(n.name) = toUpper($target_name))
                AND none(n IN nodes(p)[1..] WHERE toUpper(n.name) = toUpper($source_name))
                RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
                LIMIT 20
                """
            else:
                qh = f"""
                MATCH {src_node}, {tgt_node}
                MATCH p = (source)-[:{rel_pattern}*{h}]->(target)
                WHERE none(n IN nodes(p)[0..-2] WHERE toUpper(n.name) = toUpper($target_name))
                AND none(n IN nodes(p)[1..] WHERE toUpper(n.name) = toUpper($source_name))
                RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
                LIMIT 20
                """
            extra_records = db.run_query(qh, parameters=params) or []
            candidate_records.extend(extra_records)

    if not candidate_records:
        return None

    dcsync_cache = {}
    scored_paths = []
    seen_signatures = set()

    for record in candidate_records:
        raw_path = record.get("p")
        if not raw_path:
            continue

        nodes = [
            raw_path[i].get("name") if isinstance(raw_path[i], dict) else getattr(raw_path[i], "get", lambda k: str(raw_path[i]))("name")
            for i in range(0, len(raw_path), 2)
        ]
        if len(nodes) != len(set(nodes)):
            continue

        path = enrich_path_node_labels(raw_path, record.get("node_labels"))
        normalized = normalize_path_dcsync(path, db, cache=dcsync_cache, project_id=project_id)

        if not is_valid_path(normalized, db, project_id=project_id):
            continue

        sig = get_path_signature(normalized)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        features = extract_rf_features(normalized, db=db, project_id=project_id)
        prob_pct = compute_rf_confidence(model, features)

        if prob_pct < threshold_pct:
            continue

        scored_paths.append({
            "path": normalized,
            "features": features,
            "success_probability": prob_pct,
            "model_type": "rf",
            "model_label": "Random Forest",
            "explanation": {
                "engine": "rf",
                "summary": "Random Forest Bagging Ensemble (150 Trees)",
                "details": f"{len(RF_FEATURE_COLUMNS)} telemetry features evaluated.",
            },
        })

    scored_paths.sort(key=lambda x: x["success_probability"], reverse=True)
    return scored_paths[:10] if scored_paths else None


# Backwards compatibility alias
run_predictive = run_rf_predictive
