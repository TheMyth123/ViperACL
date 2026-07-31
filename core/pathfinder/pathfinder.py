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


# Old architecture for old test_full_chain.py to work. To be removed after complete migration to test_full_chain_new.py
class Pathfinder:
    def __init__(self, db_manager):
        self.db = db_manager
        
        self.COST_MAP = {
            # Passive / Already possessed
            'MemberOf': 0,
            'DCSync': 0,          # Following aclpwn: if you have it, it's 'free'
            'GetChanges': 0,      # Part of DCSync
            'GetChangesAll': 0,   # Part of DCSync
            
            # Active Modifications (Standard)
            'AddMember': 1,
            'GenericWrite': 1,
            'GenericAll': 1,
            'AllExtendedRights': 2,
            
            # Structural Changes (More complex)
            'WriteDacl': 2,
            'Owns': 2,
            'WriteOwner': 3,      # Requires taking ownership first
            
            # High Visibility / Destructive
            'ForceChangePassword': 5 # Very noisy, resets a user's actual password
        }

    def find_best_path(self, source_name, target_name):
        """
        Finds a path and calculates its total weight based on our COST_MAP.
        """
        # Join edges for the Cypher MATCH pattern
        edge_filter = ":" + "|:".join(self.COST_MAP.keys())
        
        # This query finds a path and uses REDUCE to sum up the weights 
        # based on the relationship types found in the path.
        query = f"""
        MATCH (source {{name: $source_name}}), (target {{name: $target_name}})
        // Find all paths up to 15 hops
        MATCH p = (source)-[*1..15]->(target)
        WHERE all(r IN relationships(p) WHERE type(r) IN keys($weight_map))
        // Calculate total weight
        WITH p, reduce(total = 0, r IN relationships(p) | total + $weight_map[type(r)]) AS pathWeight
        // Return the one with the lowest weight, then the fewest hops
        RETURN p, pathWeight
        ORDER BY pathWeight ASC, length(p) ASC
        LIMIT 1
        """
        
        params = {
            "source_name": source_name.upper(),
            "target_name": target_name.upper(),
            "weight_map": self.COST_MAP
        }
        
        return self.db.run_query(query, parameters=params)