"""
core/pathfinder/__init__.py
ViperACL Multi-Engine Pathfinder Package.
Provides heuristic and Machine Learning predictive attack path planning engines:
- Tactical (Cost Weighted)
- FastTrack (Fewest Hops)
- Random Forest (Bagging Ensemble)
- LightGBM (Gradient Boosted Trees + TreeSHAP)
- Path-Transformer (Deep Sequence Attention)
"""

from .fasttrack import run_fasttrack
from .lgbm_predictive import compute_lgbm_confidence, run_lgbm_predictive
from .pathfinder import PathfinderCoordinator
from .rf_predictive import compute_rf_confidence, run_rf_predictive
from .tactical import run_tactical
from .transformer_predictive import compute_transformer_confidence, run_transformer_predictive

__all__ = [
    "PathfinderCoordinator",
    "run_tactical",
    "run_fasttrack",
    "run_rf_predictive",
    "compute_rf_confidence",
    "run_lgbm_predictive",
    "compute_lgbm_confidence",
    "run_transformer_predictive",
    "compute_transformer_confidence",
]
