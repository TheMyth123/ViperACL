from .tactical import run_tactical
from .fasttrack import run_fasttrack
from .predictive import run_predictive

class PathfinderCoordinator:
    def __init__(self, db_manager):
        self.db = db_manager

    def find_path(self, source_name, target_name, mode="tactical", ml_model=None):
        """
        Routes the pathfinding request to the appropriate engine.
        """
        print(f"[*] Initializing ViperACL Pathfinder...")
        print(f"[*] Mode Selected: Viper {mode.capitalize()}")

        if mode == "fasttrack":
            return run_fasttrack(self.db, source_name, target_name)
        
        elif mode == "tactical":
            return run_tactical(self.db, source_name, target_name)
        
        elif mode == "predictive":
            if not ml_model:
                raise ValueError("[!] ML Model required for Predictive mode.")
            # <-- Now executes the predictive engine and returns the ranked paths
            return run_predictive(self.db, source_name, target_name, ml_model) 
            
        else:
            raise ValueError(f"[!] Invalid pathfinding mode: {mode}")
