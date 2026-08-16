"""
ViperACL Ingestor Subsystem

Handles SharpHound / Active Directory telemetry inspection, parsing, and Neo4j graph partition loading.
"""

from core.ingestor.inspector import inspect_sharphound_zip
from core.ingestor.parser import SharpHoundIngestor

__all__ = ["SharpHoundIngestor", "inspect_sharphound_zip"]
