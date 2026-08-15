"""
main.py - Desktop Application Entry Point

Launches the Zenmap Modern desktop application via PyWebView with Python-to-React IPC bridge.
"""

import argparse
import json
import logging
import sys
import webview

from backend.app import BackendAPI, create_app_window
from backend.scanner import ScannerEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
)
logger = logging.getLogger("zenmap_modern")


def parse_args():
    parser = argparse.ArgumentParser(description="Zenmap Modern - Desktop Network Topology & Security Auditor")
    parser.add_argument("--prod", action="store_true", help="Run in production mode loading frontend/dist bundle")
    parser.add_argument("--port", type=int, default=5173, help="Vite dev server port (default: 5173)")
    parser.add_argument("--check", action="store_true", help="Check CLI dependencies and exit")
    parser.add_argument("--mock", action="store_true", help="Print sample scan data and exit")
    parser.add_argument("--test-scan", type=str, metavar="TARGET", help="Run CLI test scan against target and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.check:
        scanner = ScannerEngine()
        deps = scanner.check_dependencies()
        print("=== System Dependency Diagnostics ===")
        print(json.dumps(deps, indent=2))
        sys.exit(0)

    if args.mock:
        sample = ScannerEngine.get_sample_data()
        print(f"=== Sample Scan Loaded ===")
        print(f"Hosts: {len(sample['data']['hosts'])}")
        print(f"AG Grid Rows: {len(sample['ag_grid'])}")
        print(f"Cytoscape Nodes: {len(sample['cytoscape']['nodes'])}, Edges: {len(sample['cytoscape']['edges'])}")
        sys.exit(0)

    if args.test_scan:
        api = BackendAPI()
        print(f"Executing scan on target: {args.test_scan}...")
        result = api.start_scan(target=args.test_scan)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # Launch PyWebView desktop application
    is_dev = not args.prod
    logger.info(f"Starting Zenmap Modern (mode: {'DEV (Vite)' if is_dev else 'PROD (dist)'})...")
    create_app_window(dev=is_dev, port=args.port)
    webview.start(debug=is_dev)


if __name__ == "__main__":
    main()
