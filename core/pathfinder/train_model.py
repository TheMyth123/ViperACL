"""
core/pathfinder/train_model.py
Backwards compatibility wrapper for Random Forest training.
Delegates to core.pathfinder.rf_train.
"""

from .rf_train import train_and_save_rf

# Alias for backwards compatibility
train_and_save = train_and_save_rf

if __name__ == "__main__":
    train_and_save_rf(verbose=True)