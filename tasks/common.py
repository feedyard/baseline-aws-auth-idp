import sys
import json
from pathlib import Path

def load_config(config_file):
    """Load *.json config file"""
    if Path(config_file).is_file():
        return json.loads(open(config_file).read())
    print('missing {} file.'.format(config_file))
    sys.exit(1)
