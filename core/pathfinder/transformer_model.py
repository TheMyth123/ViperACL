"""
core/pathfinder/transformer_model.py
Path-Transformer Deep Neural Network Architecture for ViperACL.
Processes Active Directory attack chains as ordered sequence tokens using
Multi-Head Self-Attention layers and outputs path operational feasibility
alongside per-hop attention focus weights.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

# Vocabulary mappings for Active Directory Graph Tokens
NODE_TYPE_VOCAB = {
    "PAD": 0,
    "USER": 1,
    "GROUP": 2,
    "COMPUTER": 3,
    "DOMAIN": 4,
    "GPO": 5,
    "OU": 6,
    "CONTAINER": 7,
    "BASE": 8,
    "UNKNOWN": 9,
}

REL_TYPE_VOCAB = {
    "PAD": 0,
    "MemberOf": 1,
    "GenericAll": 2,
    "GenericWrite": 3,
    "WriteDacl": 4,
    "WriteOwner": 5,
    "Owns": 6,
    "ForceChangePassword": 7,
    "AllExtendedRights": 8,
    "DCSync": 9,
    "GetChanges": 10,
    "GetChangesAll": 11,
    "AddMember": 12,
    "Contains": 13,
    "GPLink": 14,
    "AllowedToDelegate": 15,
    "ReadLAPSPassword": 16,
    "UNKNOWN": 17,
}


class PathTransformer(nn.Module):
    """
    Sequence-to-Probability Transformer Classifier with Multi-Head Self-Attention
    for Active Directory attack path feasibility analysis.
    """

    def __init__(
        self,
        node_vocab_size: int = len(NODE_TYPE_VOCAB) + 5,
        rel_vocab_size: int = len(REL_TYPE_VOCAB) + 5,
        d_model: int = 64,
        n_heads: int = 4,
        num_layers: int = 2,
        max_hops: int = 25,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.d_model = d_model
        self.max_hops = max_hops

        # Embeddings for source node type, relationship type, and target node type
        self.src_embedding = nn.Embedding(node_vocab_size, d_model // 4, padding_idx=0)
        self.rel_embedding = nn.Embedding(rel_vocab_size, d_model // 2, padding_idx=0)
        self.tgt_embedding = nn.Embedding(node_vocab_size, d_model // 4, padding_idx=0)

        # Continuous feature projection (cost, active/passive indicator)
        self.cost_proj = nn.Linear(2, d_model)

        # Combine embeddings
        self.hop_proj = nn.Linear(d_model * 2, d_model)

        # Positional Encoding
        self.pos_embedding = nn.Embedding(max_hops, d_model)

        # Multi-Head Attention Encoder
        self.layer_norm1 = nn.LayerNorm(d_model)
        self.attn_layers = nn.ModuleList([
            nn.MultiheadAttention(embed_dim=d_model, num_heads=n_heads, dropout=dropout, batch_first=True)
            for _ in range(num_layers)
        ])
        self.feed_forward = nn.ModuleList([
            nn.Sequential(
                nn.Linear(d_model, d_model * 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(d_model * 2, d_model),
            )
            for _ in range(num_layers)
        ])
        self.norm_layers = nn.ModuleList([
            nn.LayerNorm(d_model) for _ in range(num_layers)
        ])

        # Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

    def forward(
        self,
        src_types: torch.Tensor,     # (batch, seq_len)
        rel_types: torch.Tensor,     # (batch, seq_len)
        tgt_types: torch.Tensor,     # (batch, seq_len)
        hop_feats: torch.Tensor,     # (batch, seq_len, 2)
        mask: torch.Tensor | None = None,  # (batch, seq_len) bool
    ) -> tuple[torch.Tensor, list[torch.Tensor]]:
        """
        Forward pass returning probability logits and attention weights.
        """
        batch_size, seq_len = src_types.shape
        device = src_types.device

        # Token embeddings
        src_emb = self.src_embedding(src_types)
        rel_emb = self.rel_embedding(rel_types)
        tgt_emb = self.tgt_embedding(tgt_types)
        discrete_emb = torch.cat([src_emb, rel_emb, tgt_emb], dim=-1)  # (batch, seq_len, d_model)

        feat_emb = self.cost_proj(hop_feats)  # (batch, seq_len, d_model)
        combined = torch.cat([discrete_emb, feat_emb], dim=-1)
        x = self.hop_proj(combined)

        # Add learned positional encodings
        positions = torch.arange(seq_len, device=device).unsqueeze(0).expand(batch_size, -1)
        x = x + self.pos_embedding(positions)
        x = self.layer_norm1(x)

        # Multi-Head Attention Loop
        all_attentions = []
        for attn, ff, norm in zip(self.attn_layers, self.feed_forward, self.norm_layers):
            attn_out, attn_weights = attn(
                x, x, x,
                key_padding_mask=mask,
                need_weights=True,
                average_attn_weights=True,
            )
            x = norm(x + attn_out)
            ff_out = ff(x)
            x = norm(x + ff_out)
            all_attentions.append(attn_weights)

        # Sequence pooling (masked average or max pooling across valid hops)
        if mask is not None:
            weights = (~mask).unsqueeze(-1).float()
            pooled = (x * weights).sum(dim=1) / weights.sum(dim=1).clamp(min=1.0)
        else:
            pooled = x.mean(dim=1)

        logits = self.classifier(pooled).squeeze(-1)
        return logits, all_attentions
