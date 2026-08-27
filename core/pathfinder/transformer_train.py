"""
core/pathfinder/transformer_train.py
Path-Transformer Model Trainer for ViperACL.
Trains, validates, and serializes the deep Sequence Transformer network
using the Active Directory sequence training dataset.
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
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from core.pathfinder.transformer_model import NODE_TYPE_VOCAB, REL_TYPE_VOCAB, PathTransformer


class ADSequenceDataset(Dataset):
    """PyTorch Dataset for Active Directory attack sequences."""

    def __init__(self, jsonl_path: Path, max_hops: int = 20):
        self.samples = []
        self.max_hops = max_hops

        if not jsonl_path.exists():
            # If not yet generated, auto-generate synthetic sequence data from master generator
            from dev.generate_master_dataset import export_datasets, generate_master_dataset
            samples = generate_master_dataset()
            export_datasets(samples)

        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    self.samples.append(json.loads(line))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        item = self.samples[idx]
        hops = item["hops"]
        label = float(item["success"])

        src_tokens = []
        rel_tokens = []
        tgt_tokens = []
        feats = []

        for h in hops[:self.max_hops]:
            s_type = h.get("source_type", "USER")
            r_type = h.get("relationship", "MemberOf")
            t_type = h.get("target_type", "GROUP")
            cost = float(h.get("cost", 1))
            is_passive = float(h.get("is_passive", 0.0))

            src_tokens.append(NODE_TYPE_VOCAB.get(s_type, NODE_TYPE_VOCAB["UNKNOWN"]))
            rel_tokens.append(REL_TYPE_VOCAB.get(r_type, REL_TYPE_VOCAB["UNKNOWN"]))
            tgt_tokens.append(NODE_TYPE_VOCAB.get(t_type, NODE_TYPE_VOCAB["UNKNOWN"]))
            feats.append([cost / 5.0, is_passive])

        seq_len = len(src_tokens)
        pad_len = self.max_hops - seq_len

        # Pad sequences
        src_tokens += [0] * pad_len
        rel_tokens += [0] * pad_len
        tgt_tokens += [0] * pad_len
        feats += [[0.0, 0.0]] * pad_len
        mask = [False] * seq_len + [True] * pad_len  # True indicates padding for key_padding_mask

        return {
            "src": torch.tensor(src_tokens, dtype=torch.long),
            "rel": torch.tensor(rel_tokens, dtype=torch.long),
            "tgt": torch.tensor(tgt_tokens, dtype=torch.long),
            "feats": torch.tensor(feats, dtype=torch.float32),
            "mask": torch.tensor(mask, dtype=torch.bool),
            "label": torch.tensor(label, dtype=torch.float32),
            "seq_len": seq_len,
        }


def train_and_save_transformer(verbose: bool = True, epochs: int = 20) -> PathTransformer:
    """Trains the deep Path-Transformer model and serializes its PyTorch weights."""
    train_path = PROJECT_ROOT / "data" / "transformer_synthetic_training.jsonl"
    test_path = PROJECT_ROOT / "data" / "transformer_synthetic_testing.jsonl"
    model_path = PROJECT_ROOT / "models" / "transformer_viper_model.pt"
    model_path.parent.mkdir(parents=True, exist_ok=True)

    if verbose:
        print("=" * 75)
        print("    VIPERACL PREDICTIVE ENGINE — PATH-TRANSFORMER MODEL TRAINING")
        print("=" * 75)

    train_dataset = ADSequenceDataset(train_path)
    test_dataset = ADSequenceDataset(test_path)

    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

    if verbose:
        print(f"[*] Loaded {len(train_dataset)} training sequences, {len(test_dataset)} testing sequences.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PathTransformer(
        node_vocab_size=len(NODE_TYPE_VOCAB) + 5,
        rel_vocab_size=len(REL_TYPE_VOCAB) + 5,
        d_model=64,
        n_heads=4,
        num_layers=2,
        max_hops=25,
    ).to(device)

    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1.5e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for batch in train_loader:
            src = batch["src"].to(device)
            rel = batch["rel"].to(device)
            tgt = batch["tgt"].to(device)
            feats = batch["feats"].to(device)
            mask = batch["mask"].to(device)
            labels = batch["label"].to(device)

            optimizer.zero_grad()
            logits, _ = model(src, rel, tgt, feats, mask=mask)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(labels)
            preds = (torch.sigmoid(logits) >= 0.5).float()
            correct += (preds == labels).sum().item()
            total += len(labels)

        scheduler.step()
        epoch_acc = correct / max(1, total)
        epoch_loss = total_loss / max(1, total)

        if verbose and (epoch % 5 == 0 or epoch == epochs):
            print(f"[*] Epoch {epoch:>2}/{epochs} | Loss: {epoch_loss:.4f} | Training Accuracy: {epoch_acc*100:.1f}%")

    # Evaluation on Hold-out Test Set
    model.eval()
    test_correct = 0
    test_total = 0
    all_preds = []
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
            preds = (probs >= 0.5).float()

            test_correct += (preds == labels).sum().item()
            test_total += len(labels)
            all_preds.extend(probs.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    test_acc = test_correct / max(1, test_total)
    if verbose:
        print("-" * 75)
        print("  INDEPENDENT TEST SET GENERALIZATION METRICS")
        print("-" * 75)
        print(f"  • Validation Accuracy : {test_acc:.4f} ({test_acc*100:.1f}%)")
        print("-" * 75)

    # Save serialized weights
    torch.save(model.state_dict(), model_path)
    if verbose:
        print(f"[+] Path-Transformer weights serialized to: {model_path}")
        print("=" * 75)

    return model


if __name__ == "__main__":
    train_and_save_transformer(verbose=True, epochs=20)
