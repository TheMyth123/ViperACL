"""
core/pathfinder/rf_evaluate.py
Random Forest Predictive Model Evaluation & Analytics Utility.
Evaluates the serialized Random Forest classifier against hold-out test telemetry,
displaying classification metrics, confusion matrix, and feature importance.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from core.pathfinder.rf_predictive import RF_FEATURE_COLUMNS


def render_bar(val: float, max_val: float = 1.0, width: int = 35) -> str:
    """Renders a clean ASCII horizontal bar for metric visualization."""
    filled = int((val / max(1e-6, max_val)) * width)
    return "█" * filled + "░" * (width - filled)


def evaluate_rf_model(verbose: bool = True) -> dict:
    model_path = PROJECT_ROOT / "models" / "rf_viper_model.pkl"
    if not model_path.exists():
        model_path = PROJECT_ROOT / "models" / "viper_rf_model.pkl"

    test_path = PROJECT_ROOT / "data" / "rf_synthetic_testing.csv"
    if not test_path.exists():
        test_path = PROJECT_ROOT / "data" / "synthetic_testing.csv"

    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {model_path}. Run rf_train.py first.")
    if not test_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_path}.")

    model = joblib.load(model_path)
    df_test = pd.read_csv(test_path)
    X_test = df_test[RF_FEATURE_COLUMNS]
    y_test = df_test["Success"]

    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    inference_time_sec = time.perf_counter() - t0

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

    total_samples = len(df_test)
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
        print("RANDOM FOREST — HOLD-OUT TEST RESULTS")
        print("=" * 80)
        print(f"[*] Independent Hold-Out Test Dataset : {total_samples:,} samples")
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
        print(f"  • Total Test Samples    : {total_samples} samples")
        print(f"  • Average Time / Sample : {inference_stats['avg_time_ms']:.4f} ms ({inference_stats['samples_per_sec']:,.1f} samples/sec)")
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
        "y_true": y_test.to_numpy(),
        "y_pred": y_pred,
        "y_prob": y_prob,
        "model_name": "Random Forest",
    }


if __name__ == "__main__":
    evaluate_rf_model(verbose=True)

