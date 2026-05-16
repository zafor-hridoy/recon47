"""
Recon47 - SecLists Wordlist Manager
Author: Xaff
Auto-detects or downloads SecLists from GitHub for industry-level wordlists.
Maps each scan module to the optimal SecLists wordlist.
"""

import os
import subprocess
from core.logger import Logger


# SecLists GitHub repository
SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"

# Common install locations (Kali pre-installs here)
SECLISTS_SEARCH_PATHS = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/seclists",
    "/opt/SecLists",
    os.path.expanduser("~/SecLists"),
    os.path.expanduser("~/seclists"),
]

# Optimal wordlists for each scan type (relative to SecLists root)
WORDLIST_MAP = {
    # Subdomain enumeration — top 5000 is fast + effective
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/bitquark-subdomains-top100000.txt",
        "Discovery/DNS/namelist.txt",
    ],
    # Directory/file bruteforce — raft + common gives great coverage
    "directories": [
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/directory-list-2.3-small.txt",
    ],
    # File discovery — sensitive files, backups, configs
    "files": [
        "Discovery/Web-Content/raft-medium-files.txt",
        "Discovery/Web-Content/common.txt",
    ],
    # Parameter names for fuzzing
    "parameters": [
        "Discovery/Web-Content/burp-parameter-names.txt",
    ],
}


class SecListsManager:
    """Manages SecLists wordlist detection, download, and access."""

    _seclists_root = None
    _initialized = False

    @classmethod
    def initialize(cls):
        """Find or download SecLists. Called once at startup."""
        if cls._initialized:
            return

        # 1. Check known install paths
        for path in SECLISTS_SEARCH_PATHS:
            if os.path.isdir(path) and cls._validate_seclists(path):
                cls._seclists_root = path
                Logger.success(f"SecLists found: {path}")
                cls._initialized = True
                return

        # 2. Check if it's in the tool's own directory
        local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SecLists")
        if os.path.isdir(local_path) and cls._validate_seclists(local_path):
            cls._seclists_root = local_path
            Logger.success(f"SecLists found: {local_path}")
            cls._initialized = True
            return

        # 3. Auto-download SecLists (shallow clone for speed)
        Logger.warning("SecLists not found locally. Downloading from GitHub...")
        Logger.info("This is a one-time setup (~150MB). Please wait...")
        try:
            download_path = os.path.expanduser("~/SecLists")
            subprocess.run(
                ["git", "clone", "--depth", "1", SECLISTS_REPO, download_path],
                check=True,
                capture_output=True,
                timeout=300  # 5 min timeout
            )
            if cls._validate_seclists(download_path):
                cls._seclists_root = download_path
                Logger.success(f"SecLists downloaded to: {download_path}")
            else:
                Logger.error("SecLists download incomplete. Using fallback wordlists.")
        except FileNotFoundError:
            Logger.error("Git not installed. Install with: sudo apt install git")
            Logger.warning("Falling back to built-in wordlists.")
        except subprocess.TimeoutExpired:
            Logger.error("SecLists download timed out. Using fallback wordlists.")
        except subprocess.CalledProcessError as e:
            # Maybe it already exists but was incomplete
            if os.path.isdir(download_path):
                cls._seclists_root = download_path
                Logger.warning("SecLists directory exists, using it as-is.")
            else:
                Logger.error(f"SecLists download failed: {e}")
                Logger.warning("Falling back to built-in wordlists.")
        except Exception as e:
            Logger.error(f"SecLists setup failed: {e}")
            Logger.warning("Falling back to built-in wordlists.")

        cls._initialized = True

    @classmethod
    def get_wordlist(cls, category, max_words=None):
        """
        Get the best available wordlist for a scan category.

        Args:
            category: One of 'subdomains', 'directories', 'files', 'parameters'
            max_words: Optional limit on number of words to load

        Returns:
            list of words from the wordlist
        """
        if not cls._initialized:
            cls.initialize()

        if cls._seclists_root and category in WORDLIST_MAP:
            for relative_path in WORDLIST_MAP[category]:
                full_path = os.path.join(cls._seclists_root, relative_path)
                if os.path.isfile(full_path):
                    try:
                        words = cls._load_wordlist(full_path, max_words)
                        Logger.info(f"Loaded {len(words)} words from SecLists/{relative_path}")
                        return words
                    except Exception as e:
                        Logger.warning(f"Failed to load {relative_path}: {e}")
                        continue

        # Fallback: return None so caller uses its built-in list
        return None

    @classmethod
    def get_wordlist_path(cls, category):
        """Get the filesystem path to the best wordlist for a category."""
        if not cls._initialized:
            cls.initialize()

        if cls._seclists_root and category in WORDLIST_MAP:
            for relative_path in WORDLIST_MAP[category]:
                full_path = os.path.join(cls._seclists_root, relative_path)
                if os.path.isfile(full_path):
                    return full_path
        return None

    @staticmethod
    def _load_wordlist(filepath, max_words=None):
        """Load words from a file, one per line."""
        words = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
                    if max_words and len(words) >= max_words:
                        break
        return words

    @staticmethod
    def _validate_seclists(path):
        """Check if a path looks like a valid SecLists install."""
        # Check for key directories that should exist
        checks = [
            os.path.isdir(os.path.join(path, "Discovery")),
            os.path.isdir(os.path.join(path, "Discovery", "DNS")),
            os.path.isdir(os.path.join(path, "Discovery", "Web-Content")),
        ]
        return all(checks)

    @classmethod
    def is_available(cls):
        """Check if SecLists is available."""
        if not cls._initialized:
            cls.initialize()
        return cls._seclists_root is not None

    @classmethod
    def get_root(cls):
        """Get the SecLists root directory path."""
        return cls._seclists_root
