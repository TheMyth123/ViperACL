"""
core/pathfinder/evaluate_model.py
Backwards compatibility wrapper for Random Forest evaluation.
Delegates to core.pathfinder.rf_evaluate.
"""

from .rf_evaluate import evaluate_rf_model

# Alias for backwards compatibility
evaluate_predictive_model = evaluate_rf_model

if __name__ == "__main__":
    evaluate_rf_model(verbose=True)
