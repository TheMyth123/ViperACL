"""
core/pathfinder/transformer_evaluate.py
Path-Transformer Model Evaluation & Attention Analysis Utility.
Evaluates the serialized PyTorch Path-Transformer on hold-out sequence test data,
displaying classification metrics, confusion matrix, and sequence attention patterns.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
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

    if verbose:
        print("=" * 80)
        print("     VIPERACL PATH-TRANSFORMER — BENCHMARK & METRICS EVALUATION")
        print("=" * 80)
        print(f"[*] Evaluated on Independent Test Dataset : {len(y_test):,} sequences")
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
    evaluate_transformer_model(verbose=True)
