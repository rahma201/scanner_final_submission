from __future__ import annotations

from scanner.port_scanner import run_scan
from scanner.checks import ALL_CHECKS
from scanner.cve.cve_mapper import map_cves
from scanner.models import HostResult, PortService, Finding
from scanner.report.reporter import Reporter


def integrate_scan(target: str, service: str | None = None, version: str | None = None):
    raw_results = run_scan(target)
    final_results: list[HostResult] = []

    for ip, data in raw_results.items():
        host_result = HostResult(host=ip)

        for port in data.get("open_ports", []):
            host_result.open_ports.append(PortService(port=port, service="unknown"))

        for check in ALL_CHECKS:
            msg = check(ip)
            if msg:
                host_result.findings.append(
                    Finding(
                        id=check.__name__,
                        title=msg,
                        severity="High",
                        type="misconfiguration",
                    )
                )

        if service and version:
            cves = map_cves(service, version)
            for c in cves:
                host_result.findings.append(
                    Finding(
                        id=c["cve_id"],
                        title=c["description"],
                        severity=c["severity"].capitalize(),
                        type="cve",
                        references=[c["reference"]],
                        affected={"service": service, "version": version},
                    )
                )

        final_results.append(host_result)

    return final_results


def main():
    while True:
        target = input("Enter target IP or CIDR: ").strip()
        if target:
            break
        print("Target cannot be empty. Example: 127.0.0.1 or 192.168.1.0/24")

    svc = input("Service name for CVE mapping (optional, e.g. apache): ").strip() or None
    ver = input("Service version (optional, e.g. 2.4.49): ").strip() or None

    if (svc and not ver) or (ver and not svc):
        print("Note: CVE mapping will run only if BOTH service and version are provided.")
        svc = None
        ver = None

    results = integrate_scan(target, svc, ver)

    reporter = Reporter()
    reporter.terminal_summary(results)
    print("Risk Rating:", reporter.risk_rating(results))


if __name__ == "__main__":
    main()
