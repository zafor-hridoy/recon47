"""
Recon47 - Port Scanner Module
Author: Xaff
TCP connect port scanner with service detection and multi-threading.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import TOP_100_PORTS
from core.logger import Logger


# Common service banners mapped to ports
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 512: "rexec", 513: "rlogin", 514: "syslog",
    548: "AFP", 554: "RTSP", 587: "Submission", 631: "IPP",
    636: "LDAPS", 873: "rsync", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 1900: "UPnP",
    2049: "NFS", 3000: "Node/Dev", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC-1", 6000: "X11", 6379: "Redis",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "WebConsole", 9200: "Elasticsearch", 9999: "HTTP-Alt",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB", 28017: "MongoDB-Web"
}


class PortScanner:
    """Multi-threaded TCP connect port scanner."""

    def __init__(self, target, ports=None, threads=10, timeout=3):
        self.target = target
        self.ports = ports or TOP_100_PORTS
        self.threads = threads
        self.timeout = min(timeout, 5)  # Cap at 5s for port scanning
        self.results = []

    def run(self):
        """Scan all specified ports and return results."""
        Logger.info(f"Scanning {len(self.ports)} ports on {self.target}...")

        with Logger.progress("Port Scanning") as progress:
            task = progress.add_task("Scanning ports", total=len(self.ports))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._scan_port, port): port
                    for port in self.ports
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.results.append(result)
                    progress.update(task, advance=1)

        # Sort by port number
        self.results.sort(key=lambda x: x["port"])

        # Display results
        open_ports = [r for r in self.results if r["state"] == "open"]
        if open_ports:
            rows = []
            for p in open_ports:
                rows.append((
                    str(p["port"]),
                    p["state"].upper(),
                    p.get("service", "unknown"),
                    p.get("banner", "")[:50]
                ))
            Logger.table("Open Ports",
                         ["Port", "State", "Service", "Banner"], rows)
        else:
            Logger.warning("No open ports found")

        return self.results

    def _scan_port(self, port):
        """Scan a single port. Returns result dict if open, else None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = COMMON_SERVICES.get(port, "unknown")
                banner = self._grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
            else:
                sock.close()
                return {
                    "port": port,
                    "state": "closed",
                    "service": COMMON_SERVICES.get(port, "unknown"),
                    "banner": ""
                }
        except socket.timeout:
            return {
                "port": port,
                "state": "filtered",
                "service": COMMON_SERVICES.get(port, "unknown"),
                "banner": ""
            }
        except Exception:
            return None

    def _grab_banner(self, sock, port):
        """Attempt to grab a service banner from an open port."""
        try:
            # Send probe for HTTP ports
            if port in (80, 8080, 8000, 8008, 8081, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            else:
                sock.sendall(b"\r\n")

            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            # Clean up banner - take first line only
            if banner:
                return banner.split("\n")[0][:100]
        except Exception:
            pass
        return ""
