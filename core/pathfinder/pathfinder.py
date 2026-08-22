from .tactical import run_tactical
from .fasttrack import run_fasttrack
from .predictive import run_predictive

class PathfinderCoordinator:
    def __init__(self, db_manager):
        self.db = db_manager

    def find_path(self, source_name, target_name, mode="tactical", ml_model=None, max_hops=15, ml_threshold=0.50):
        """
        Routes the pathfinding request to the appropriate engine.
        """
        if mode == "fasttrack":
            return run_fasttrack(self.db, source_name, target_name, max_hops=max_hops)
        
        elif mode == "tactical":
            return run_tactical(self.db, source_name, target_name, max_hops=max_hops)
        
        elif mode == "predictive":
            if not ml_model:
                raise ValueError("[!] ML Model required for Predictive mode.")
            return run_predictive(self.db, source_name, target_name, ml_model, max_hops=max_hops, ml_threshold=ml_threshold) 
            
        else:
            raise ValueError(f"[!] Invalid pathfinding mode: {mode}")
