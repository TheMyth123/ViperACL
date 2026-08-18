import os
import sys
import joblib

# Forces Python to add your root ViperACL folder to its search path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.database import DatabaseManager
from core.pathfinder.pathfinder import PathfinderCoordinator

def print_path_results(results, mode):
    if not results:
        print("[-] No exploitable path found.")
        print("-" * 50)
        return

    # Handle the Predictive Engine output (List of ranked paths)
    if mode == 'predictive':
        print(f"[+] Evaluated and ranked {len(results)} candidate paths:")
        for rank, record in enumerate(results, 1):
            path = record['path']
            prob = record['success_probability']
            steps = (len(path) - 1) // 2
            
            print(f"\n  Rank {rank} | Success Probability: {prob}% | {steps} Steps")
            for i in range(0, len(path) - 2, 2):
                start_node = path[i]['name']
                rel_type = path[i + 1]
                end_node = path[i + 2]['name']
                print(f"    {start_node} --[{rel_type}]--> {end_node}")
                
    # Handle FastTrack & Tactical output (Single path)
    else:
        record = results[0]
        path = record['p']
        
        metric = f"Total Weight: {record.get('pathWeight')}" if mode == 'tactical' else f"Total Hops: {record.get('hops')}"
        steps = (len(path) - 1) // 2
        
        print(f"[+] Found a path with {steps} steps! ({metric})")
        for i in range(0, len(path) - 2, 2):
            start_node = path[i]['name']
            rel_type = path[i + 1]
            end_node = path[i + 2]['name']
            print(f"  {start_node} --[{rel_type}]--> {end_node}")
            
    print("-" * 50)

if __name__ == "__main__":
    db = DatabaseManager()
    if db.connect():
        pf = PathfinderCoordinator(db)
        model_path = os.path.join(project_root, 'models', 'viper_rf_model.pkl')
        rf_model = None
        try:
            rf_model = joblib.load(model_path)
            print(f"[*] Successfully loaded ML model from {model_path}")
        except Exception as e:
            print(f"[!] Warning: Could not load ML model: {e}")

        test_cases = [
            ("MIKE_INTERN@VIPERTECH.LOCAL", "VIPERTECH.LOCAL", "Targeting Domain Root"),
        ]

        for source, target, label in test_cases:
            print(f"\n{'='*55}\n[*] Scenario: {label}\n[*] Path: {source} -> {target}\n{'='*55}\n")

            # 1. Test Viper Tactical
            tactical_results = pf.find_path(source, target, mode="tactical")
            print_path_results(tactical_results, "tactical")

            # 2. Test Viper FastTrack
            fasttrack_results = pf.find_path(source, target, mode="fasttrack")
            print_path_results(fasttrack_results, "fasttrack")

            # 3. Test Viper Predictive (ML)
            if rf_model:
                predictive_results = pf.find_path(source, target, mode="predictive", ml_model=rf_model, ml_threshold=0.00)
                print_path_results(predictive_results, "predictive")