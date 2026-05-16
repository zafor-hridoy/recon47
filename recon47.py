#!/usr/bin/env python3
"""
Recon47 - Automated Reconnaissance & Vulnerability Scanner
Author: Xaff
Version: 1.0.0

Main CLI entry point. Run: python recon47.py -t <target>
"""

import sys
import os
import argparse
import warnings

# Fix Windows console encoding for Unicode output
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

# Suppress SSL warnings for pentesting use
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, TOOL_DESCRIPTION
from core.engine import ScanEngine
from core.logger import Logger


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} -- {TOOL_DESCRIPTION} by {TOOL_AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon47.py -t example.com
  python recon47.py -t https://example.com -o results --threads 20
  python recon47.py -t 192.168.1.1 --nikto --nuclei
  python recon47.py -t example.com --stealth --depth 5
  python recon47.py -t example.com --skip-vuln
        """
    )

    # Required arguments
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain, URL, or IP address"
    )

    # Output options
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output directory (default: recon47_output)"
    )

    # Scan tuning
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Number of threads (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Crawler depth (default: 3)"
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help="Max requests per second (default: 15)"
    )

    # Phase control
    parser.add_argument(
        "--skip-recon",
        action="store_true",
        help="Skip reconnaissance phase"
    )
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip crawling phase"
    )
    parser.add_argument(
        "--skip-vuln",
        action="store_true",
        help="Skip vulnerability scanning phase"
    )

    # External tools
    parser.add_argument(
        "--nikto",
        action="store_true",
        help="Enable Nikto vulnerability scanner"
    )
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help="Enable Nuclei vulnerability scanner"
    )

    # Stealth mode
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Enable stealth mode (slower, evasive scanning)"
    )

    # Display options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress ASCII banner"
    )

    return parser.parse_args()


def main():
    """Main entry point for Recon47."""
    try:
        args = parse_args()

        # Suppress urllib3 InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Create and run scan engine
        engine = ScanEngine(args)
        engine.run()

    except KeyboardInterrupt:
        Logger.warning("\n\n  Scan interrupted by user (Ctrl+C). Exiting...")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Fatal error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
