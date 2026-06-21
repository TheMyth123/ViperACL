"""Maps SharpHound edge types to their handler module class.

Each module must implement: execute(self, rel, context) -> bool
"""
import importlib

EDGE_MODULE_MAP = {
    # passive.py
    "MemberOf": ("passive", "PassiveModule"),
    "DCSync": ("passive", "PassiveModule"),
    "GetChangesAll": ("passive", "PassiveModule"),
    # standard.py
    "AddMember": ("standard", "StandardModule"),
    "GenericWrite": ("standard", "StandardModule"),
    "GenericAll": ("standard", "StandardModule"),
    # structural.py
    "WriteDacl": ("structural", "StructuralModule"),
    "Owns": ("structural", "StructuralModule"),
    "WriteOwner": ("structural", "StructuralModule"),
    # destructive.py
    "ForceChangePassword": ("destructive", "DestructiveModule"),
}


def get_module(edge_type: str, engine):
    """Instantiate the handler module mapped to an edge type."""
    entry = EDGE_MODULE_MAP.get(edge_type)
    if not entry:
        raise ValueError(f"No module mapped for edge type: {edge_type}")
    mod_name, cls_name = entry
    module = importlib.import_module(f"core.privesc.modules.{mod_name}")
    cls = getattr(module, cls_name)
    return cls(engine)