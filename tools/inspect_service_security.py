"""Inspect only the four fixed service slots; never alter their permissions."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.windows.service_security import Reader


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    value=Reader().inspect()
    with args.output.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
    print(json.dumps(value))
