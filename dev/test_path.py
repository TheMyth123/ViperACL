# dev/test_path.py
import sys
import os
import joblib

# Forces Python to add your root ViperACL folder to its search path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from utils.database import DatabaseManager
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
        
        source = "WLEY@INLANEFREIGHT.LOCAL"
        target = "ADUNN@INLANEFREIGHT.LOCAL"
        
        print(f"\nTargeting: {source} -> {target}\n")

        # 1. Test Viper Tactical
        tactical_results = pf.find_path(source, target, mode="tactical")
        print_path_results(tactical_results, "tactical")

        # 2. Test Viper FastTrack
        fasttrack_results = pf.find_path(source, target, mode="fasttrack")
        print_path_results(fasttrack_results, "fasttrack")

        # 3. Test Viper Predictive (ML)
        model_path = os.path.join(project_root, 'models', 'viper_rf_model.pkl')
        try:
            rf_model = joblib.load(model_path)
            print(f"[*] Successfully loaded ML model from {model_path}")
            
            predictive_results = pf.find_path(source, target, mode="predictive", ml_model=rf_model)
            print_path_results(predictive_results, "predictive")
            
        except FileNotFoundError:
            print(f"[!] ML Model not found at {model_path}. Run train_model.py first.")
        except Exception as e:
            print(f"[!] Error loading Predictive Engine: {e}")