#!/usr/bin/env python3
"""Prepare/verify pinned Forge inputs; compile only via explicit --build."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('trusted_backport_builder', Path(__file__).with_name('build-backports.py'))
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--prepare', type=Path)
    action.add_argument('--verify-prepared', type=Path)
    action.add_argument('--verify-tools', type=Path)
    action.add_argument('--build', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--node', type=Path)
    parser.add_argument('--npm-package', type=Path, help='Existing npm package.json; never executes npm')
    args = parser.parse_args()
    root = ROOT / 'tools/dependency-backports'
    try:
        record = b.load_manifest(root)['packages'][1]
        recipe, unused_source = b.forge_recipe(root, record)
        if not args.build:
            b.require(args.output is None and args.node is None and args.npm_package is None)
            if args.prepare:
                result = b.prepare_forge(root, record, args.prepare)
            elif args.verify_prepared:
                source = b.verify_forge_prepared(root, record, args.verify_prepared)
                result = {'verified': True, 'source_files': len(source), 'compiler_executed': False}
            else:
                result = b.verify_forge_tools(root, record, args.verify_tools)
        else:
            b.require(args.output is not None and args.node is not None and args.npm_package is not None)
            b.require(not os.environ.get('NODE_OPTIONS') and not os.environ.get('NODE_PATH'))
            b.verify_forge_tools(root, record, args.build)
            b.require(args.node.is_absolute() and args.node.resolve().is_file())
            b.require(args.npm_package.is_absolute() and args.npm_package.name == 'package.json')
            npm = b.json_data(args.npm_package.read_bytes())
            b.require(npm['name'] == 'npm' and npm['version'] == recipe['runtime']['npm'])
            output = args.output.absolute()
            b.forge_new_parent(output)
            b.require(not output.is_relative_to(args.build.absolute()))
            # subprocess inherits the entire actual environment, including the exact
            # presence and values of HOME/CODEX_HOME. No config/environment rewrite.
            completed = subprocess.run([str(args.node.resolve()), str(root / recipe['compiler_script']),
                str(args.build.absolute()), str(output)], cwd=ROOT, check=False)
            b.require(completed.returncode == 0)
            b.verify_forge_tools(root, record, args.build)
            result = b.check_forge_outputs(root, record, output, with_receipts=True)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (b.BackportError, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({'verified': False, 'error': 'forge producer verification failed'}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
