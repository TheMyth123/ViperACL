"""
core/pathfinder/pathfinder.py
Central Pathfinder Coordinator and Dispatcher for ViperACL.
Routes pathfinding requests to Tactical, FastTrack, Random Forest, LightGBM,
or Path-Transformer predictive scoring engines.
"""

from __future__ import annotations

from typing import Any

from .fasttrack import run_fasttrack
from .lgbm_predictive import run_lgbm_predictive
from .rf_predictive import run_rf_predictive
from .tactical import run_tactical
from .transformer_predictive import run_transformer_predictive


class PathfinderCoordinator:
    """Dispatches pathfinding queries across heuristic and machine learning scoring engines."""

    def __init__(self, db_manager: Any):
        self.db = db_manager

    def find_path(
        self,
        source_name: str,
        target_name: str,
        mode: str = "tactical",
        ml_model: Any = None,
        ml_explainer: Any = None,
        max_hops: int = 15,
        ml_threshold: float = 0.50,
        project_id: str | None = None,
    ) -> list[dict] | None:
        """
        Routes the pathfinding query to the requested heuristic or ML engine:
        - 'fasttrack' / 'fewest_hops': Breadth-first shortest path
        - 'tactical' / 'lowest_cost': Dijkstra-style cost-weighted pathfinding
        - 'predictive_rf' / 'rf' / 'predictive': Random Forest probability scoring
        - 'predictive_lgbm' / 'lgbm': LightGBM gradient boosted scoring with TreeSHAP
        - 'predictive_transformer' / 'transformer': Deep Path-Transformer sequence attention scoring
        """
        clean_mode = (mode or "tactical").lower().strip()

        if clean_mode in ("fasttrack", "fewest_hops"):
            return run_fasttrack(self.db, source_name, target_name, max_hops=max_hops, project_id=project_id)

        elif clean_mode in ("tactical", "lowest_cost"):
            return run_tactical(self.db, source_name, target_name, max_hops=max_hops, project_id=project_id)

        elif clean_mode in ("predictive_rf", "rf", "predictive"):
            if not ml_model:
                raise ValueError("[!] Random Forest model is required for RF predictive pathfinding.")
            return run_rf_predictive(
                self.db,
                source_name,
                target_name,
                model=ml_model,
                max_hops=max_hops,
                ml_threshold=ml_threshold,
                project_id=project_id,
            )

        elif clean_mode in ("predictive_lgbm", "lgbm"):
            if not ml_model:
                raise ValueError("[!] LightGBM model is required for LightGBM predictive pathfinding.")
            return run_lgbm_predictive(
                self.db,
                source_name,
                target_name,
                model=ml_model,
                explainer=ml_explainer,
                max_hops=max_hops,
                ml_threshold=ml_threshold,
                project_id=project_id,
            )

        elif clean_mode in ("predictive_transformer", "transformer"):
            if not ml_model:
                raise ValueError("[!] Path-Transformer PyTorch model is required for Transformer pathfinding.")
            return run_transformer_predictive(
                self.db,
                source_name,
                target_name,
                model=ml_model,
                max_hops=max_hops,
                ml_threshold=ml_threshold,
                project_id=project_id,
            )

        else:
            raise ValueError(f"[!] Invalid pathfinding mode: '{mode}'. Choose from: tactical, fasttrack, predictive_rf, predictive_lgbm, predictive_transformer.")
