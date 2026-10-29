"""Collect the current candidate's pinned CPython source, without executing it."""
from fetch_go_source import fetch
import argparse

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--security-candidate',action='store_true')
    args=parser.parse_args()
    fetch('python-security-candidate-lock.json' if args.security_candidate else 'python-source-lock.json')
