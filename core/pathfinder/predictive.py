"""
core/pathfinder/predictive.py
Backwards compatibility layer for Random Forest Predictive Pathfinder.
Re-exports functionality from core.pathfinder.rf_predictive.
"""

from .rf_predictive import (
    FEATURE_COLUMNS,
    REL_TYPES,
    RF_FEATURE_COLUMNS,
    RF_REL_TYPES,
    compute_path_confidence,
    compute_rf_confidence,
    extract_features,
    extract_rf_features,
    run_predictive,
    run_rf_predictive,
)

__all__ = [
    "RF_FEATURE_COLUMNS",
    "RF_REL_TYPES",
    "FEATURE_COLUMNS",
    "REL_TYPES",
    "extract_rf_features",
    "extract_features",
    "compute_rf_confidence",
    "compute_path_confidence",
    "run_rf_predictive",
    "run_predictive",
]