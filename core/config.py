"""
Recon47 - Configuration Module
Author: Xaff
Central configuration for all scan parameters and defaults.
"""

import os

# ─── Tool Metadata ─────────────────────────────────────────────
TOOL_NAME = "Recon47"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "Xaff"
TOOL_DESCRIPTION = "Automated Reconnaissance & Vulnerability Scanner"

# ─── Default Scan Settings ─────────────────────────────────────
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_CRAWL_DEPTH = 3
DEFAULT_RATE_LIMIT = 15  # requests per second
DEFAULT_OUTPUT_DIR = "recon47_output"

# ─── Port Scanning ─────────────────────────────────────────────
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 162, 179, 199, 389, 443, 445, 465,
    512, 513, 514, 515, 548, 554, 587, 631, 636,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
    1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
    3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 5901, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9090, 9100, 9200, 9999, 10000, 10443,
    11211, 27017, 27018, 28017, 32768, 49152, 49153,
    49154, 49155, 49156, 49157
]

# ─── User-Agent Rotation Pool ──────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
]

# ─── Security Headers to Check ─────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "MEDIUM",
        "recommendation": "Implement a Content-Security-Policy header to prevent XSS and data injection attacks"
    },
    "X-Content-Type-Options": {
        "description": "X-Content-Type-Options",
        "severity": "LOW",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header"
    },
    "X-Frame-Options": {
        "description": "X-Frame-Options (Clickjacking Protection)",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header"
    },
    "X-XSS-Protection": {
        "description": "X-XSS-Protection",
        "severity": "LOW",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header"
    },
    "Referrer-Policy": {
        "description": "Referrer Policy",
        "severity": "LOW",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header"
    },
    "Permissions-Policy": {
        "description": "Permissions Policy (formerly Feature-Policy)",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy header to control browser features"
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Cross-Domain Policy",
        "severity": "LOW",
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none' header"
    }
}

# ─── Technology Signatures ──────────────────────────────────────
TECH_SIGNATURES = {
    # Web Servers
    "Apache": {"headers": ["Apache"], "meta": []},
    "Nginx": {"headers": ["nginx"], "meta": []},
    "IIS": {"headers": ["Microsoft-IIS"], "meta": []},
    "LiteSpeed": {"headers": ["LiteSpeed"], "meta": []},
    "Cloudflare": {"headers": ["cloudflare"], "meta": []},
    
    # Frameworks
    "WordPress": {"headers": [], "meta": ["wp-content", "wp-includes", "wordpress"]},
    "Drupal": {"headers": ["X-Drupal"], "meta": ["drupal", "Drupal.settings"]},
    "Joomla": {"headers": [], "meta": ["joomla", "/media/system/js/"]},
    "Django": {"headers": ["csrftoken"], "meta": ["csrfmiddlewaretoken"]},
    "Laravel": {"headers": ["laravel_session"], "meta": []},
    "Express.js": {"headers": ["X-Powered-By: Express"], "meta": []},
    "ASP.NET": {"headers": ["X-AspNet-Version", "X-Powered-By: ASP.NET"], "meta": ["__VIEWSTATE"]},
    "React": {"headers": [], "meta": ["_reactRoot", "react-root", "__NEXT_DATA__"]},
    "Vue.js": {"headers": [], "meta": ["vue-app", "v-app", "__vue__"]},
    "Angular": {"headers": [], "meta": ["ng-app", "ng-version", "angular"]},
    
    # CDN / Hosting
    "AWS": {"headers": ["AmazonS3", "x-amz-"], "meta": ["amazonaws.com"]},
    "Google Cloud": {"headers": ["x-goog-"], "meta": ["googleapis.com"]},
    "Vercel": {"headers": ["x-vercel-"], "meta": []},
    "Netlify": {"headers": ["x-nf-"], "meta": []},
    
    # JavaScript Libraries
    "jQuery": {"headers": [], "meta": ["jquery"]},
    "Bootstrap": {"headers": [], "meta": ["bootstrap"]},
    "Tailwind CSS": {"headers": [], "meta": ["tailwindcss"]},
    
    # Analytics
    "Google Analytics": {"headers": [], "meta": ["google-analytics.com", "gtag", "UA-", "G-"]},
    "Google Tag Manager": {"headers": [], "meta": ["googletagmanager.com"]},
    
    # Security
    "reCAPTCHA": {"headers": [], "meta": ["recaptcha", "g-recaptcha"]},
    "hCaptcha": {"headers": [], "meta": ["hcaptcha"]},
}

# ─── Common Directory/File Wordlist ────────────────────────────
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "cpanel", "phpmyadmin", "adminer",
    "api", "api/v1", "api/v2", "graphql", "swagger",
    "backup", "backups", "bak", "old", "temp", "tmp",
    "config", "configuration", "conf", "settings",
    ".env", ".git", ".git/HEAD", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt", "humans.txt",
    "uploads", "upload", "files", "images", "media", "assets",
    "static", "public", "private", "data", "database",
    "test", "testing", "debug", "dev", "staging",
    "docs", "documentation", "readme", "changelog",
    "server-status", "server-info", "info.php", "phpinfo.php",
    "wp-content", "wp-includes", "wp-json",
    "cgi-bin", "scripts", "bin",
    "console", "shell", "terminal",
    "log", "logs", "error_log", "access_log",
    ".DS_Store", "web.config", "Thumbs.db",
    "vendor", "node_modules", "package.json", "composer.json",
    "xmlrpc.php", "readme.html", "license.txt",
]

# ─── Common Subdomains Wordlist ─────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
    "webmail", "admin", "blog", "shop", "forum", "api",
    "dev", "staging", "test", "beta", "demo", "app",
    "cdn", "media", "static", "assets", "img", "images",
    "portal", "secure", "vpn", "remote", "gateway",
    "db", "database", "sql", "mysql", "postgres",
    "git", "svn", "repo", "jenkins", "ci", "cd",
    "monitor", "status", "health", "metrics", "grafana",
    "docs", "wiki", "help", "support", "kb",
    "login", "auth", "sso", "oauth", "id",
    "m", "mobile", "wap",
    "intranet", "internal", "corp", "office",
    "cloud", "aws", "azure", "gcp",
    "proxy", "cache", "edge", "lb", "load",
    "mx", "mx1", "mx2", "relay",
    "backup", "bak", "old", "new", "v2",
    "web", "web1", "web2", "server", "server1",
    "cpanel", "whm", "plesk",
    "store", "pay", "payment", "billing",
    "crm", "erp", "hr",
]

# ─── Severity Levels ────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#ff0040",
    "HIGH": "#ff4444",
    "MEDIUM": "#ffaa00",
    "LOW": "#00d4ff",
    "INFO": "#888888"
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}
