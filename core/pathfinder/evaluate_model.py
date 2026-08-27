"""
core/pathfinder/evaluate_model.py
Unified Multi-Engine Machine Learning Evaluator for ViperACL.

Benchmarks and compares all 3 predictive pathfinding architectures on hold-out test datasets:
1. Random Forest (150 Bagged Trees)
2. LightGBM (Gradient Boosted Trees + TreeSHAP)
3. Path-Transformer (Deep Multi-Head Self-Attention)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.pathfinder.lgbm_evaluate import evaluate_lgbm_model
from core.pathfinder.rf_evaluate import evaluate_rf_model
from core.pathfinder.transformer_evaluate import evaluate_transformer_model


def render_metric_row(name: str, rf_val: float, lgbm_val: float, trans_val: float, is_pct: bool = True) -> str:
    """Formats a comparative row across the three ML models."""
    if is_pct:
        rf_str = f"{rf_val * 100:6.2f}%"
        lgbm_str = f"{lgbm_val * 100:6.2f}%"
        trans_str = f"{trans_val * 100:6.2f}%"
    else:
        rf_str = f"{rf_val:7.4f}"
        lgbm_str = f"{lgbm_val:7.4f}"
        trans_str = f"{trans_val:7.4f}"

    return f"  │ {name:<26} │ {rf_str:^16} │ {lgbm_str:^16} │ {trans_str:^16} │"


def evaluate_all_models(verbose: bool = True) -> dict[str, dict]:
    """
    Executes benchmark evaluation across Random Forest, LightGBM, and Path-Transformer
    against the independent hold-out test dataset, presenting a consolidated comparison table.
    """
    if verbose:
        print("=" * 80)
        print("     VIPERACL PREDICTIVE ENGINE — UNIFIED MULTI-MODEL BENCHMARK")
        print("=" * 80)
        print("  Evaluating models on hold-out test datasets...\n")

    # Evaluate individual models on independent test sets
    rf_results = evaluate_rf_model(verbose=False)
    lgbm_results = evaluate_lgbm_model(verbose=False)
    trans_results = evaluate_transformer_model(verbose=False)

    if verbose:
        print("=" * 80)
        print("  CONSOLIDATED CLASSIFICATION & GENERALIZATION BENCHMARKS")
        print("=" * 80)
        print("  ┌────────────────────────────┬──────────────────┬──────────────────┬──────────────────┐")
        print("  │ Metric                     │  Random Forest   │     LightGBM     │ Path-Transformer │")
        print("  ├────────────────────────────┼──────────────────┼──────────────────┼──────────────────┤")
        print(render_metric_row("Test Accuracy", rf_results["accuracy"], lgbm_results["accuracy"], trans_results["accuracy"]))
        print(render_metric_row("Precision Score", rf_results["precision"], lgbm_results["precision"], trans_results["precision"]))
        print(render_metric_row("Recall (Sensitivity)", rf_results["recall"], lgbm_results["recall"], trans_results["recall"]))
        print(render_metric_row("F1 Classification", rf_results["f1"], lgbm_results["f1"], trans_results["f1"]))
        print(render_metric_row("ROC-AUC Score", rf_results["roc_auc"], lgbm_results["roc_auc"], trans_results["roc_auc"]))
        print("  └────────────────────────────┴──────────────────┴──────────────────┴──────────────────┘")
        print("=" * 80)
        print("[✓] Multi-model evaluation and benchmark comparison complete.\n")

    return {
        "random_forest": rf_results,
        "lightgbm": lgbm_results,
        "transformer": trans_results,
    }


# Backwards compatibility alias
evaluate_predictive_model = evaluate_all_models
evaluate_rf_model_compat = evaluate_rf_model


if __name__ == "__main__":
    evaluate_all_models(verbose=True)
