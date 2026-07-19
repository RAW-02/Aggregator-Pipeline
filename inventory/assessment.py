from inventory.models import ComponentReport, InventorySummary


class RiskAssessment:

    def calculate(self, components: list[ComponentReport]) -> InventorySummary:
        total = len(components)
        affected = 0
        kev = 0
        exploitable = 0
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for component in components:
            if component.vulnerabilities:
                affected += 1

            for vuln in component.vulnerabilities:

                severity = vuln.severity.upper()
                if severity in severity_count:
                    severity_count[severity] += 1

                if vuln.kev:
                    kev += 1

                if vuln.exploit_available:
                    exploitable += 1

        for component in components:
            component.risk_level = self.determine_risk(component.highest_threat_score)

        components.sort(
            key=lambda component: component.highest_threat_score, reverse=True
        )

        highest = components[0].highest_threat_score if components else 0

        overall_risk = self.determine_risk(highest)

        return InventorySummary(
            total_components=total,
            affected_components=affected,
            critical=severity_count["CRITICAL"],
            high=severity_count["HIGH"],
            medium=severity_count["MEDIUM"],
            low=severity_count["LOW"],
            kev=kev,
            exploitable=exploitable,
            overall_risk=overall_risk,
            overall_threat_score=highest,
        )

    def determine_risk(self, score: float) -> str:
        if score >= 90:
            return "CRITICAL"

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"
