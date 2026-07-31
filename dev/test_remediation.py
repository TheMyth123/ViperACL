import sys
import os
import joblib
import logging

# This forces Python to add your root ViperACL folder to its search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database import DatabaseManager
from core.pathfinder.pathfinder import PathfinderCoordinator
from core.remediation.engine import RemediationEngine

logging.basicConfig(level=logging.INFO, format="%(message)s")

# CONFIGURATION
DC_IP = "172.16.5.5"
DOMAIN = "INLANEFREIGHT.LOCAL"
SOURCE_USER = "INLANEFREIGHT\\WLEY"
SOURCE_PASS = "transporter@4"

# 1. Setup & Connection to Neo4j
db = DatabaseManager()
db.connect()
pf = PathfinderCoordinator(db)

# Load the Random Forest Machine Learning Model
model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "viper_rf_model.pkl")
rf_model = joblib.load(model_path)

logging.info("[*] Querying Neo4j for predictive paths...")
ranked_paths = pf.find_path(
    "WLEY@INLANEFREIGHT.LOCAL",
    "ADUNN@INLANEFREIGHT.LOCAL",
    mode="predictive",
    ml_model=rf_model,
)

if not ranked_paths or len(ranked_paths) < 2:
    raise RuntimeError("Predictive mode did not return a rank 2 path.")

# Extract the second path (Rank 2) as requested
rank2_path = ranked_paths[1]["path"]
rank2_score = ranked_paths[1]["success_probability"]

logging.info("[*] Selected predictive rank 2 path")
logging.info(f"[*] Success Probability: {rank2_score}%\n")

# 2. Extract relationships from the Path Object
extracted_relationships = []

# If the path is a raw Neo4j Path object
if hasattr(rank2_path, 'relationships'):
    for rel in rank2_path.relationships:
        src = rel.start_node.get('name', 'UnknownSource').split('@')[0]
        tgt = rel.end_node.get('name', 'UnknownTarget').split('@')[0]
        extracted_relationships.append({'type': rel.type, 'source': src, 'target': tgt})

# If the ML model flattened it into a list: [Node, Rel, Node, Rel, Node]
elif isinstance(rank2_path, list):
    if len(rank2_path) % 2 != 0:
        for i in range(0, len(rank2_path) - 1, 2):
            src_node = rank2_path[i]
            edge = rank2_path[i+1]
            tgt_node = rank2_path[i+2]

            # Safely extract names and STRIP THE DOMAIN (@INLANEFREIGHT.LOCAL)
            if hasattr(src_node, 'get'): 
                src_name = src_node.get('name', str(src_node)).split('@')[0]
            else: 
                src_name = str(src_node).split('@')[0]

            if hasattr(tgt_node, 'get'): 
                tgt_name = tgt_node.get('name', str(tgt_node)).split('@')[0]
            else: 
                tgt_name = str(tgt_node).split('@')[0]
            
            # Extract edge type
            if hasattr(edge, 'type'): rel_type = edge.type
            elif isinstance(edge, dict): rel_type = edge.get('type', str(edge))
            else: rel_type = str(edge)
            
            extracted_relationships.append({
                'type': rel_type,
                'source': src_name,
                'target': tgt_name
            })
    else:
        # Fallback if it's a standard list of dictionary edges
        for rel in rank2_path:
            if isinstance(rel, dict):
                extracted_relationships.append({
                    'type': rel.get('type', 'UnknownType'),
                    'source': rel.get('source', 'UnknownSource').split('@')[0],
                    'target': rel.get('target', 'UnknownTarget').split('@')[0]
                })

# 3. Interactive Command-Line Interface (CLI)
print("=" * 60)
print(" VIPERACL AUTOMATED REMEDIATION INTERFACE")
print("=" * 60)
print(f"Target Path Success Probability: {rank2_score}%")
print("Identified ACL Security Flaws:\n")

for idx, rel in enumerate(extracted_relationships):
    print(f"  [{idx}] {rel['source']} --({rel['type']})--> {rel['target']}")

print("\nRemediation Options:")
print("  - Select specific numbers separated by commas to compile individual fixes (e.g., 0,2)")
print("  - Type 'all' to mitigate all security risks along this path")
print("  - Type 'q' to abort process")

choice = input("\nSelect actions to compile into remediation script: ").strip().lower()

if choice == 'q':
    print("[*] Operation canceled by user. Exiting...")
    sys.exit(0)

# 4. Filter and build target remediation list based on choice
selected_targets = []
if choice == 'all':
    selected_targets = extracted_relationships
else:
    try:
        indices = [int(x.strip()) for x in choice.split(',')]
        for i in indices:
            if 0 <= i < len(extracted_relationships):
                selected_targets.append(extracted_relationships[i])
            else:
                print(f"[!] Warning: Index {i} is out of bounds and will be omitted.")
    except ValueError:
        print("[!] Error: Invalid selection syntax. Terminating process.")
        sys.exit(1)

# 5. Hand over to Remediation Engine
print("\n" + "=" * 60)
remediation_engine = RemediationEngine(output_dir="scripts")
success = remediation_engine.generate_script(selected_targets)
print("=" * 60)