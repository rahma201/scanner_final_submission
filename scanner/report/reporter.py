from __future__ import annotations

import json
from dataclasses import asdict
from typing import Dict, List

from scanner.models import HostResult, SEVERITY_SCORE


class Reporter:
    def terminal_summary(self, results: List[HostResult]) -> None:
        print("\n=== Scan Summary ===")
        for r in results:
            print(f"\nHost: {r.host} | Reachable: {r.reachable}")
            if r.errors:
                print("  Errors:")
                for e in r.errors:
                    print(f"   - {e}")

            if r.open_ports:
                print("  Open Ports:")
                for p in r.open_ports:
                    ver = f" {p.version}" if p.version else ""
                    svc = f"{p.service}{ver}"
                    print(f"   - {p.port}/{p.proto}  {svc}")

            if r.findings:
                print("  Findings:")
                for f in r.findings:
                    print(f"   - [{f.severity}] {f.title} ({f.type})")
            else:
                print("  Findings: None")

        print("\n=== End ===\n")

    def to_json(self, results: List[HostResult]) -> str:
        return json.dumps([asdict(r) for r in results], indent=2)

    def risk_rating(self, results: List[HostResult]) -> Dict[str, int]:
        """
        Returns a simple risk score per host based on max finding severity.
        """
        rating: Dict[str, int] = {}
        for r in results:
            best = 0
            for f in r.findings:
                best = max(best, SEVERITY_SCORE.get(str(f.severity), 0))
            rating[r.host] = best
        return rating
