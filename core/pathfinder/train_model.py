"""ViperACL Enterprise Machine Learning Model Trainer.

Trains, validates, and serializes the predictive Active Directory attack path
feasibility model using the enterprise telemetry feature dataset.
"""

import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score

from core.pathfinder.predictive import FEATURE_COLUMNS


def train_and_save(verbose: bool = True) -> RandomForestClassifier:
    """Trains the enterprise Random Forest model and serializes the brain artifact."""
    train_path = PROJECT_ROOT / "data" / "synthetic_training.csv"
    test_path = PROJECT_ROOT / "data" / "synthetic_testing.csv"
    model_path = PROJECT_ROOT / "models" / "viper_rf_model.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)

    if verbose:
        print("=" * 75)
        print("    VIPERACL PREDICTIVE ENGINE — MODEL TRAINING & OPTIMIZATION")
        print("=" * 75)

    # 1. Ingest Telemetry Dataset
    if not train_path.exists():
        raise FileNotFoundError(f"Training telemetry dataset not found at {train_path}")

    df_train = pd.read_csv(train_path)
    X_train = df_train[FEATURE_COLUMNS]
    y_train = df_train["Success"]

    if verbose:
        print(f"[*] Ingested training dataset: {len(df_train)} samples across {len(FEATURE_COLUMNS)} telemetry features.")
        print(f"    Class Balance: Success=1: {sum(y_train == 1)} ({sum(y_train == 1)/len(y_train):.1%}), "
              f"Success=0: {sum(y_train == 0)} ({sum(y_train == 0)/len(y_train):.1%})")

    # 2. Configure Balanced Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=8,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        bootstrap=True,
        oob_score=True,
        random_state=42,
        n_jobs=1,
    )

    # 3. 5-Fold Stratified Cross-Validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf_model, X_train, y_train, cv=cv, scoring="accuracy", n_jobs=1)
    cv_auc = cross_val_score(rf_model, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=1)

    if verbose:
        print(f"[*] 5-Fold Stratified CV Accuracy : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        print(f"[*] 5-Fold Stratified CV ROC-AUC  : {cv_auc.mean():.4f} (+/- {cv_auc.std():.4f})")

    # 4. Fit Final Ensemble Model
    rf_model.fit(X_train, y_train)
    if verbose and hasattr(rf_model, "oob_score_"):
        print(f"[*] Out-Of-Bag (OOB) Generalization Score: {rf_model.oob_score_:.4f}")

    # 5. Independent Validation
    if test_path.exists():
        df_test = pd.read_csv(test_path)
        X_test = df_test[FEATURE_COLUMNS]
        y_test = df_test["Success"]
        y_pred = rf_model.predict(X_test)
        y_prob = rf_model.predict_proba(X_test)[:, 1]

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

    # 6. Feature Importance Summary
    if verbose:
        importances = pd.Series(rf_model.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
        print("  TOP 10 MOST INFLUENTIAL TELEMETRY RISK FACTORS")
        print("-" * 75)
        for rank, (feat, imp) in enumerate(importances.head(10).items(), 1):
            bar = "█" * int(imp * 35)
            print(f"  {rank:>2}. {feat:<32} : {imp:.4f} {bar}")

    # 7. Serialize Artifact
    joblib.dump(rf_model, model_path)
    if verbose:
        print("-" * 75)
        print(f"[+] Model artifact successfully serialized to: {model_path}")
        print("=" * 75)

    return rf_model


if __name__ == "__main__":
    train_and_save(verbose=True)