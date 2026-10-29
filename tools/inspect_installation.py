"""Record fixed service/path collisions without elevation or any mutation."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from claude_reset.install_inventory import inspect


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect()
    # Evidence is new-only; never silently replace a prior snapshot.
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({'services_inspected': len(result['services']),
        'fresh_install_blockers': len(result['fresh_install_blockers']), 'settings_changed': False}))
