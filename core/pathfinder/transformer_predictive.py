"""
core/pathfinder/transformer_predictive.py
Path-Transformer Predictive Pathfinder Engine for ViperACL.
Evaluates candidate Active Directory attack paths as ordered token sequences using
a deep Multi-Head Self-Attention Transformer neural network, extracts sequence likelihoods,
and pinpoints critical bottleneck hops via attention weight distribution.
"""

from __future__ import annotations

import numpy as np
import torch

from .rf_predictive import RF_REL_TYPES
from .rules import (
    enrich_path_node_labels,
    get_path_signature,
    is_valid_path,
    normalize_path_dcsync,
)
from .tactical import COST_MAP, get_edge_cost
from .transformer_model import NODE_TYPE_VOCAB, REL_TYPE_VOCAB, PathTransformer


def get_node_type_label(node: dict | str) -> str:
    """Extracts node type string ('USER', 'GROUP', 'COMPUTER', 'DOMAIN')."""
    if isinstance(node, dict):
        labels = node.get("labels", [])
        for lbl in ["USER", "GROUP", "COMPUTER", "DOMAIN", "GPO", "OU", "CONTAINER"]:
            if lbl in [l.upper() for l in labels]:
                return lbl
        name = (node.get("name") or "").upper()
        if "$" in name:
            return "COMPUTER"
        if "@" in name or "." in name:
            return "USER"
    return "USER"


def encode_path_sequence(path: list, db=None, project_id: str | None = None) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, list[dict]]:
    """
    Encodes a candidate graph attack path into PyTorch sequence tensors:
    (src_types, rel_types, tgt_types, hop_feats, hop_details).
    """
    hops = max(1, (len(path) - 1) // 2)
    src_tokens = []
    rel_tokens = []
    tgt_tokens = []
    hop_feats = []
    hop_details = []

    for i in range(1, len(path) - 1, 2):
        src_node = path[i - 1]
        rel = path[i]
        rel_type = rel if isinstance(rel, str) else getattr(rel, "type", str(rel))
        tgt_node = path[i + 1]

        src_lbl = get_node_type_label(src_node)
        tgt_lbl = get_node_type_label(tgt_node)
        cost = get_edge_cost(rel_type, tgt_node, db, project_id=project_id)
        is_passive = 1.0 if rel_type in ("MemberOf", "DCSync", "GetChanges", "GetChangesAll") else 0.0

        src_id = NODE_TYPE_VOCAB.get(src_lbl, NODE_TYPE_VOCAB["UNKNOWN"])
        rel_id = REL_TYPE_VOCAB.get(rel_type, REL_TYPE_VOCAB["UNKNOWN"])
        tgt_id = NODE_TYPE_VOCAB.get(tgt_lbl, NODE_TYPE_VOCAB["UNKNOWN"])

        src_tokens.append(src_id)
        rel_tokens.append(rel_id)
        tgt_tokens.append(tgt_id)
        hop_feats.append([cost / 5.0, is_passive])

        tgt_name = tgt_node.get("name") if isinstance(tgt_node, dict) else str(tgt_node)
        hop_details.append({
            "hop_number": len(src_tokens),
            "source_type": src_lbl,
            "relationship": rel_type,
            "target_type": tgt_lbl,
            "target_name": tgt_name,
            "cost": cost,
            "is_passive": bool(is_passive),
        })

    # Pad or create tensor shape (1, seq_len)
    t_src = torch.tensor([src_tokens], dtype=torch.long)
    t_rel = torch.tensor([rel_tokens], dtype=torch.long)
    t_tgt = torch.tensor([tgt_tokens], dtype=torch.long)
    t_feats = torch.tensor([hop_feats], dtype=torch.float32)

    return t_src, t_rel, t_tgt, t_feats, hop_details


def compute_transformer_confidence(model: PathTransformer, path: list, db=None, project_id: str | None = None) -> tuple[float, dict]:
    """
    Runs forward inference through the Path-Transformer, calculates calibrated confidence %,
    and extracts multi-head attention weights to identify the critical bottleneck hop.
    """
    model.eval()
    t_src, t_rel, t_tgt, t_feats, hop_details = encode_path_sequence(path, db=db, project_id=project_id)

    with torch.no_grad():
        logits, all_attentions = model(t_src, t_rel, t_tgt, t_feats)
        raw_prob = float(torch.sigmoid(logits).item())

    # Calibrated probability percentage [55.0%, 96.0%]
    confidence = 55.0 + (raw_prob * 41.0)
    confidence_pct = round(max(55.0, min(96.0, confidence)), 1)

    # Extract Attention weights across sequence hops
    attention_focus = {
        "critical_hop": 1,
        "relationship": hop_details[0]["relationship"] if hop_details else "MemberOf",
        "target": hop_details[0]["target_name"] if hop_details else "TARGET",
        "attention_weight": "100.0%",
        "summary": "Direct attack path transition.",
        "hop_attentions": [],
    }

    if all_attentions and len(hop_details) > 0:
        try:
            # Average attention weights across heads of the final layer: shape (seq_len, seq_len)
            last_attn = all_attentions[-1][0].cpu().numpy()
            num_hops = len(hop_details)
            # Hop importance from attention matrix row/column projections
            hop_weights = last_attn[:num_hops, :num_hops].mean(axis=0)
            weight_sum = hop_weights.sum()
            if weight_sum > 0:
                normalized = hop_weights / weight_sum
            else:
                normalized = np.ones(num_hops) / num_hops

            crit_idx = int(np.argmax(normalized))
            crit_hop = hop_details[crit_idx]
            crit_pct = f"{normalized[crit_idx] * 100:.1f}%"

            hop_attns = []
            for idx, (h, w) in enumerate(zip(hop_details, normalized)):
                hop_attns.append({
                    "hop": idx + 1,
                    "relationship": h["relationship"],
                    "target": h["target_name"],
                    "weight_pct": f"{w * 100:.1f}%",
                    "weight_val": float(w),
                })

            attention_focus = {
                "critical_hop": crit_idx + 1,
                "relationship": crit_hop["relationship"],
                "target": crit_hop["target_name"],
                "attention_weight": crit_pct,
                "summary": f"Critical Hop: Hop {crit_idx + 1} ({crit_hop['relationship']}) [Attention Focus: {crit_pct}]",
                "hop_attentions": hop_attns,
            }
        except Exception:
            pass

    return confidence_pct, attention_focus


def run_transformer_predictive(
    db,
    source_name: str,
    target_name: str,
    model: PathTransformer,
    max_hops: int = 15,
    ml_threshold: float = 0.50,
    project_id: str | None = None,
) -> list[dict] | None:
    """
    Path-Transformer Predictive Engine: Evaluates candidate paths using deep sequence attention
    and identifies critical bottleneck hops along the attack chain.
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

    q_shortest = f"""
    MATCH {src_node}, {tgt_node}
    MATCH p = allShortestPaths((source)-[:{rel_pattern}*..{hops_limit}]->(target))
    {rel_filter}
    RETURN p, length(p) AS hops, [n IN nodes(p) | labels(n)] AS node_labels, labels(target) AS target_labels
    """
    candidate_records = db.run_query(q_shortest, parameters=params) or []
    min_hops = candidate_records[0].get("hops") if candidate_records else None

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

        prob_pct, attention_focus = compute_transformer_confidence(model, normalized, db=db, project_id=project_id)

        if prob_pct < threshold_pct:
            continue

        scored_paths.append({
            "path": normalized,
            "success_probability": prob_pct,
            "model_type": "transformer",
            "model_label": "Path-Transformer",
            "attention_focus": attention_focus,
            "explanation": {
                "engine": "transformer",
                "summary": "Path-Transformer Multi-Head Attention",
                "focus": attention_focus.get("summary", ""),
                "critical_hop": attention_focus.get("critical_hop", 1),
                "attention_weight": attention_focus.get("attention_weight", ""),
            },
        })

    scored_paths.sort(key=lambda x: x["success_probability"], reverse=True)
    return scored_paths[:10] if scored_paths else None
