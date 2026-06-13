import yaml
import os

def load_config(config_path='config.yaml'):
    """Loads the configuration file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file {config_path} not found.")
    
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)
