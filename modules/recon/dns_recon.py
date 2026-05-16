"""
Recon47 - DNS Reconnaissance Module
Author: Xaff
Enumerates DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA) for a target domain.
"""

import dns.resolver
import dns.reversename
from core.logger import Logger


class DNSRecon:
    """DNS record enumeration and analysis."""

    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def run(self):
        results = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "PTR": []}
        for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        results[rtype].append({"priority": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")})
                    elif rtype == "SOA":
                        results[rtype].append({"mname": str(rdata.mname).rstrip("."), "rname": str(rdata.rname).rstrip("."), "serial": rdata.serial})
                    else:
                        results[rtype].append(str(rdata).rstrip(".").strip('"'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        for ip in results["A"]:
            try:
                rev = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev, "PTR")
                for rdata in answers:
                    results["PTR"].append({"ip": ip, "hostname": str(rdata).rstrip(".")})
            except Exception:
                pass

        self._display(results)
        return results

    def _display(self, results):
        rows = []
        for rtype in ["A", "AAAA", "CNAME", "NS", "TXT"]:
            for r in results[rtype]:
                val = r if isinstance(r, str) else str(r)
                rows.append((rtype, val[:80]))
        for mx in results["MX"]:
            rows.append(("MX", f"{mx['exchange']} (pri: {mx['priority']})"))
        for soa in results["SOA"]:
            rows.append(("SOA", f"Primary: {soa['mname']}"))
        for ptr in results["PTR"]:
            rows.append(("PTR", f"{ptr['ip']} -> {ptr['hostname']}"))
        if rows:
            Logger.table("DNS Records", ["Type", "Value"], rows)
