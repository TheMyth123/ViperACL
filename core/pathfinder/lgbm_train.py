"""
core/pathfinder/lgbm_train.py
LightGBM Model Trainer with TreeSHAP Explainer for ViperACL.
Trains, validates, and serializes the LightGBM Gradient Boosted classifier
and its TreeSHAP explainer using the LGBM enterprise telemetry dataset.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import lightgbm as lgb
import pandas as pd
import shap
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score

from core.pathfinder.lgbm_predictive import LGBM_FEATURE_COLUMNS


def train_and_save_lgbm(verbose: bool = True) -> tuple[lgb.LGBMClassifier, shap.TreeExplainer]:
    """Trains the enterprise LightGBM model and serializes model & TreeSHAP explainer."""
    train_path = PROJECT_ROOT / "data" / "lgbm_synthetic_training.csv"
    test_path = PROJECT_ROOT / "data" / "lgbm_synthetic_testing.csv"
    model_path = PROJECT_ROOT / "models" / "lgbm_viper_model.pkl"
    explainer_path = PROJECT_ROOT / "models" / "lgbm_shap_explainer.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)

    if verbose:
        print("=" * 75)
        print("    VIPERACL PREDICTIVE ENGINE — LIGHTGBM & TREESHAP TRAINING")
        print("=" * 75)

    if not train_path.exists():
        raise FileNotFoundError(f"Training telemetry dataset not found at {train_path}")

    df_train = pd.read_csv(train_path)
    X_train = df_train[LGBM_FEATURE_COLUMNS]
    y_train = df_train["Success"]

    if verbose:
        print(f"[*] Ingested training dataset: {len(df_train)} samples across {len(LGBM_FEATURE_COLUMNS)} telemetry features.")
        print(f"    Class Balance: Success=1: {sum(y_train == 1)} ({sum(y_train == 1)/len(y_train):.1%}), "
              f"Success=0: {sum(y_train == 0)} ({sum(y_train == 0)/len(y_train):.1%})")

    lgbm_model = lgb.LGBMClassifier(
        n_estimators=120,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=6,
        min_child_samples=5,
        class_weight="balanced",
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        verbose=-1,
    )

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(lgbm_model, X_train, y_train, cv=cv, scoring="accuracy")
        cv_auc = cross_val_score(lgbm_model, X_train, y_train, cv=cv, scoring="roc_auc")

        if verbose:
            print(f"[*] 5-Fold Stratified CV Accuracy : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
            print(f"[*] 5-Fold Stratified CV ROC-AUC  : {cv_auc.mean():.4f} (+/- {cv_auc.std():.4f})")

        lgbm_model.fit(X_train, y_train)

        # Fit TreeSHAP Explainer
        explainer = shap.TreeExplainer(lgbm_model)

    if test_path.exists():
        df_test = pd.read_csv(test_path)
        X_test = df_test[LGBM_FEATURE_COLUMNS]
        y_test = df_test["Success"]
        y_pred = lgbm_model.predict(X_test)
        y_prob = lgbm_model.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_prob)

        if verbose:
            print("-" * 75)
            print("  INDEPENDENT TEST SET GENERALIZATION METRICS")
            print("-" * 75)
            print(f"  • Validation Accuracy : {acc:.4f}")
            print(f"  • Precision Score     : {prec:.4f}")
            print(f"  • Recall Score        : {rec:.4f}")
            print(f"  • F1 Classification   : {f1:.4f}")
            print(f"  • ROC-AUC Score       : {auc:.4f}")
            print("-" * 75)

    joblib.dump(lgbm_model, model_path)
    joblib.dump(explainer, explainer_path)
    if verbose:
        print(f"[+] LightGBM model serialized to: {model_path}")
        print(f"[+] TreeSHAP explainer serialized to: {explainer_path}")
        print("=" * 75)

    return lgbm_model, explainer


if __name__ == "__main__":
    train_and_save_lgbm(verbose=True)
