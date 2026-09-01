"""
core/pathfinder/transformer_evaluate.py
Path-Transformer Model Evaluation & Attention Analysis Utility.
Evaluates the serialized PyTorch Path-Transformer on hold-out sequence test data,
displaying classification metrics, confusion matrix, and sequence attention patterns.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.utils.data import DataLoader

from core.pathfinder.transformer_model import NODE_TYPE_VOCAB, REL_TYPE_VOCAB, PathTransformer
from core.pathfinder.transformer_train import ADSequenceDataset


def render_bar(val: float, max_val: float = 1.0, width: int = 35) -> str:
    """Renders a clean ASCII horizontal bar for metric visualization."""
    filled = int((val / max(1e-6, max_val)) * width)
    return "█" * filled + "░" * (width - filled)


def evaluate_transformer_model(verbose: bool = True) -> dict:
    model_path = PROJECT_ROOT / "models" / "transformer_viper_model.pt"
    test_path = PROJECT_ROOT / "data" / "transformer_synthetic_testing.jsonl"

    if not model_path.exists():
        raise FileNotFoundError(f"Transformer model artifact not found at {model_path}. Run transformer_train.py first.")
    if not test_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_path}.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PathTransformer(
        node_vocab_size=len(NODE_TYPE_VOCAB) + 5,
        rel_vocab_size=len(REL_TYPE_VOCAB) + 5,
        d_model=64,
        n_heads=4,
        num_layers=2,
        max_hops=25,
    ).to(device)

    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()

    test_dataset = ADSequenceDataset(test_path)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

    all_probs = []
    all_labels = []

    t0 = time.perf_counter()
    with torch.no_grad():
        for batch in test_loader:
            src = batch["src"].to(device)
            rel = batch["rel"].to(device)
            tgt = batch["tgt"].to(device)
            feats = batch["feats"].to(device)
            mask = batch["mask"].to(device)
            labels = batch["label"].to(device)

            logits, _ = model(src, rel, tgt, feats, mask=mask)
            probs = torch.sigmoid(logits)

            all_probs.extend(probs.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    inference_time_sec = time.perf_counter() - t0

    y_test = np.array(all_labels)
    y_prob = np.array(all_probs)
    y_pred = (y_prob >= 0.5).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    clf_report_str = classification_report(
        y_test, y_pred, target_names=["Fail (0)", "Pass (1)"], digits=4, zero_division=0
    )
    clf_report_dict = classification_report(
        y_test, y_pred, target_names=["Fail (0)", "Pass (1)"], output_dict=True, zero_division=0
    )

    total_samples = len(y_test)
    fail_count = int(sum(y_test == 0))
    pass_count = int(sum(y_test == 1))

    dataset_info = {
        "total_samples": total_samples,
        "num_classes": 2,
        "class_labels": ["Fail (0)", "Pass (1)"],
        "class_counts": {"Fail (0)": fail_count, "Pass (1)": pass_count},
        "class_percentages": {
            "Fail (0)": round((fail_count / total_samples) * 100, 2),
            "Pass (1)": round((pass_count / total_samples) * 100, 2),
        },
    }

    inference_stats = {
        "total_time_ms": round(inference_time_sec * 1000, 2),
        "avg_time_ms": round((inference_time_sec / total_samples) * 1000, 4),
        "samples_per_sec": round(total_samples / max(inference_time_sec, 1e-9), 1),
    }

    if verbose:
        print("=" * 80)
        print("PATH-TRANSFORMER — HOLD-OUT TEST RESULTS")
        print("=" * 80)
        print(f"[*] Independent Hold-Out Test Dataset : {total_samples:,} sequences")
        print(f"[*] Class Distribution (Ground Truth) :")
        print(f"    • Fail (0) : {fail_count:>4} samples ({fail_count / total_samples * 100:5.2f}%)")
        print(f"    • Pass (1) : {pass_count:>4} samples ({pass_count / total_samples * 100:5.2f}%)")
        print("-" * 80)
        print("  CLASSIFICATION PERFORMANCE METRICS:")
        print("-" * 80)
        print(f"  • Test Accuracy       : {acc*100:6.2f}%  [{render_bar(acc)}]")
        print(f"  • Precision Score     : {prec*100:6.2f}%  [{render_bar(prec)}]")
        print(f"  • Recall (Sensitivity): {rec*100:6.2f}%  [{render_bar(rec)}]")
        print(f"  • F1-Score            : {f1*100:6.2f}%  [{render_bar(f1)}]")
        print(f"  • ROC-AUC Score       : {auc*100:6.2f}%  [{render_bar(auc)}]")
        print("-" * 80)
        print("  CONFUSION MATRIX & DETAILED COUNTS:")
        print("-" * 80)
        print(f"  Raw Matrix (2x2):")
        print(f"    [[{tn:>4}, {fp:>4}],")
        print(f"     [{fn:>4}, {tp:>4}]]\n")
        print(f"  Explicit Quadrant Breakdown:")
        print(f"    • True Negatives  (TN) : {tn:>4}  ({tn/total_samples*100:5.2f}%)  [Correctly identified impossible paths]")
        print(f"    • False Positives (FP) : {fp:>4}  ({fp/total_samples*100:5.2f}%)  [False alarms / over-optimistic paths]")
        print(f"    • False Negatives (FN) : {fn:>4}  ({fn/total_samples*100:5.2f}%)  [Missed viable attack paths]")
        print(f"    • True Positives  (TP) : {tp:>4}  ({tp/total_samples*100:5.2f}%)  [Correctly validated viable paths]")
        print(f"    • Total Test Samples   : {total_samples:>4}  (100.00%)  [TN + FP + FN + TP = {tn + fp + fn + tp}]")
        print()
        print(f"  Heatmap Layout:")
        print(f"                     ┌─────────────────────┬─────────────────────┐")
        print(f"                     │   PREDICTED FAIL    │   PREDICTED PASS    │")
        print(f"  ┌──────────────────┼─────────────────────┼─────────────────────┤")
        print(f"  │ ACTUAL FAIL (0)  │  TN = {tn:<6} ({tn/total_samples*100:4.1f}%) │  FP = {fp:<6} ({fp/total_samples*100:4.1f}%) │")
        print(f"  ├──────────────────┼─────────────────────┼─────────────────────┤")
        print(f"  │ ACTUAL PASS (1)  │  FN = {fn:<6} ({fn/total_samples*100:4.1f}%) │  TP = {tp:<6} ({tp/total_samples*100:4.1f}%) │")
        print(f"  └──────────────────┴─────────────────────┴─────────────────────┘")
        print("-" * 80)
        print("  SKLEARN CLASSIFICATION REPORT:")
        print("-" * 80)
        print(clf_report_str.rstrip())
        print("-" * 80)
        print("  INFERENCE LATENCY & THROUGHPUT:")
        print("-" * 80)
        print(f"  • Total Prediction Time : {inference_stats['total_time_ms']:.2f} ms")
        print(f"  • Total Test Samples    : {total_samples} sequences")
        print(f"  • Average Time / Sample : {inference_stats['avg_time_ms']:.4f} ms ({inference_stats['samples_per_sec']:,.1f} sequences/sec)")
        print("=" * 80)

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": cm,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "classification_report": clf_report_str,
        "classification_report_dict": clf_report_dict,
        "dataset_info": dataset_info,
        "inference_stats": inference_stats,
        "y_true": y_test,
        "y_pred": y_pred,
        "y_prob": y_prob,
        "model_name": "Path-Transformer",
    }


if __name__ == "__main__":
    evaluate_transformer_model(verbose=True)

