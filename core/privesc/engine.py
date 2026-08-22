"""Core Task Manager: builds and executes the step queue for a discovered path."""
import logging
from types import SimpleNamespace

from core.privesc.factory import get_module
from core.privesc.modules.shared import PrivescActions


class PrivescEngine:
    def __init__(self, conn, domain, dc_ip, context):
        self.conn = conn          # active LDAP connection
        self.domain = domain
        self.dc_ip = dc_ip
        self.context = context    # SessionContext instance
        self.task_queue = []      # list of (rel, module)

    def build_plan(self, path_results):
        """Flatten a path into an ordered list of (relationship, module)."""
        path = path_results[0]["p"]
        for rel in self._iter_relationships(path):
            module = get_module(rel.type, self)
            self.task_queue.append((rel, module))

    def _iter_relationships(self, path):
        """
        Normalize supported path formats to relationship-like objects.

        Supported inputs:
        - Neo4j Path object with `.relationships`
        - Predictive list format: [node, rel_type, node, rel_type, node, ...]
        """
        if hasattr(path, "relationships"):
            return path.relationships

        if isinstance(path, list):
            rels = []
            for i in range(0, len(path) - 2, 2):
                rel_type = path[i + 1]
                start_node = PrivescActions._node_to_dict(path[i])
                end_node = PrivescActions._node_to_dict(path[i + 2])
                rels.append(SimpleNamespace(type=rel_type, start_node=start_node, end_node=end_node))
            return rels

        raise TypeError("Unsupported path format: expected Neo4j Path or predictive list path")

    def execute_all(self) -> bool:
        total = len(self.task_queue)
        logging.info(f"=== PRIVESC START: {total} steps ===")

        for i, (rel, module) in enumerate(self.task_queue, 1):
            target = (
                rel.end_node.get("name")
                or rel.end_node.get("distinguishedname")
                or rel.start_node.get("name")
                or rel.start_node.get("distinguishedname")
            )
            logging.info(f"[{i}/{total}] {rel.type} -> {target}")

            success = module.execute(rel, self.context)

            if not success:
                logging.error(f"FAILED at step {i} ({rel.type} -> {target}). Aborting.")
                return False

        logging.info("=== PRIVESC COMPLETE ===")
        return True