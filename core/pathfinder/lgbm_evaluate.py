"""
core/pathfinder/lgbm_evaluate.py
LightGBM Predictive Model Evaluation & Analytics Utility.
Evaluates the serialized LightGBM classifier against hold-out test telemetry,
displaying classification metrics, confusion matrix, and top SHAP feature impacts.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from core.pathfinder.lgbm_predictive import LGBM_FEATURE_COLUMNS, SHAP_FEATURE_LABELS


def render_bar(val: float, max_val: float = 1.0, width: int = 35) -> str:
    """Renders a clean ASCII horizontal bar for metric visualization."""
    filled = int((val / max(1e-6, max_val)) * width)
    return "█" * filled + "░" * (width - filled)


def evaluate_lgbm_model(verbose: bool = True) -> dict:
    model_path = PROJECT_ROOT / "models" / "lgbm_viper_model.pkl"
    explainer_path = PROJECT_ROOT / "models" / "lgbm_shap_explainer.pkl"
    test_path = PROJECT_ROOT / "data" / "lgbm_synthetic_testing.csv"

    if not model_path.exists():
        raise FileNotFoundError(f"LightGBM model artifact not found at {model_path}. Run lgbm_train.py first.")
    if not test_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_path}.")

    model = joblib.load(model_path)
    df_test = pd.read_csv(test_path)
    X_test = df_test[LGBM_FEATURE_COLUMNS]
    y_test = df_test["Success"]

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    if verbose:
        print("=" * 80)
        print("     VIPERACL LIGHTGBM + TREESHAP — BENCHMARK & METRICS EVALUATION")
        print("=" * 80)
        print(f"[*] Evaluated on Independent Test Dataset : {len(df_test):,} samples")
        print(f"[*] Ground Truth Class Distribution       : Success=1: {sum(y_test == 1):,} | Success=0: {sum(y_test == 0):,}")
        print("-" * 80)
        print(f"  • Test Accuracy : {acc*100:6.2f}%  [{render_bar(acc)}]")
        print(f"  • Precision     : {prec*100:6.2f}%  [{render_bar(prec)}]")
        print(f"  • Recall (Sens) : {rec*100:6.2f}%  [{render_bar(rec)}]")
        print(f"  • F1-Score      : {f1*100:6.2f}%  [{render_bar(f1)}]")
        print(f"  • ROC-AUC Score : {auc*100:6.2f}%  [{render_bar(auc)}]")
        print("-" * 80)
        print(f"  CONFUSION MATRIX HEATMAP:")
        print("-" * 80)
        print(f"                     ┌─────────────────────┬─────────────────────┐")
        print(f"                     │   PREDICTED FAIL    │   PREDICTED PASS    │")
        print(f"  ┌──────────────────┼─────────────────────┼─────────────────────┤")
        print(f"  │ ACTUAL FAIL (0)  │  TN = {tn:<6} ({tn/len(y_test)*100:4.1f}%) │  FP = {fp:<6} ({fp/len(y_test)*100:4.1f}%) │")
        print(f"  ├──────────────────┼─────────────────────┼─────────────────────┤")
        print(f"  │ ACTUAL PASS (1)  │  FN = {fn:<6} ({fn/len(y_test)*100:4.1f}%) │  TP = {tp:<6} ({tp/len(y_test)*100:4.1f}%) │")
        print(f"  └──────────────────┴─────────────────────┴─────────────────────┘")
        print("-" * 80)

        # Global Feature Importance from LightGBM
        importances = pd.Series(model.feature_importances_, index=LGBM_FEATURE_COLUMNS).sort_values(ascending=False)
        max_imp = importances.max()
        print("  TOP 10 LIGHTGBM SPLIT IMPORTANCES:")
        print("-" * 80)
        for rank, (feat, imp) in enumerate(importances.head(10).items(), 1):
            label = SHAP_FEATURE_LABELS.get(feat, feat)
            bar = render_bar(imp, max_val=max_imp, width=30)
            print(f"  {rank:>2}. {label:<38} │ {bar} │ {imp:>4} splits")
        print("=" * 80)

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": cm,
    }


if __name__ == "__main__":
    evaluate_lgbm_model(verbose=True)
