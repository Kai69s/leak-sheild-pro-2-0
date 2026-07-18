from dataclasses import dataclass

from app.engines.detection.scanner import DetectionFinding


SEVERITY_BASE = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 88,
}

HIGH_RISK_CONTEXT = ("production", "prod", "live", "public repo", "github", "exposed", "main branch")
LOW_RISK_CONTEXT = ("test", "dev", "development", "staging", "sandbox", "local")


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    adjustments: list[str]


class RiskEngine:
    def score_finding(self, finding: DetectionFinding, full_content: str, metadata: dict) -> RiskResult:
        base = SEVERITY_BASE[finding.rule.severity]
        score = base * finding.rule.confidence
        adjustments: list[str] = []
        context_blob = " ".join(
            [
                full_content[max(0, full_content.find(finding.secret_value) - 180) : full_content.find(finding.secret_value) + 180],
                str(metadata),
                finding.context_snippet,
            ]
        ).lower()

        if any(term in context_blob for term in HIGH_RISK_CONTEXT):
            score += 15
            adjustments.append("High-risk deployment or exposure context detected.")
        if any(term in context_blob for term in LOW_RISK_CONTEXT):
            score -= 10
            adjustments.append("Non-production context reduced the final risk.")
        if finding.rule.secret_type in {"Private Key", "Database URL", "AWS Secret Access Key", "Password"}:
            score += 8
            adjustments.append("Secret type has direct authentication impact.")
        if len(finding.secret_value) > 80:
            score += 3
            adjustments.append("Long credential material indicates a token or key payload.")

        bounded = round(max(0, min(score, 100)), 2)
        return RiskResult(score=bounded, level=self.level_for_score(bounded), adjustments=adjustments)

    def score_scan(self, findings: list[RiskResult]) -> RiskResult:
        if not findings:
            return RiskResult(score=0, level="LOW", adjustments=["No secrets were detected."])
        highest = max(item.score for item in findings)
        density_bonus = min(12, (len(findings) - 1) * 3)
        score = round(min(100, highest + density_bonus), 2)
        return RiskResult(
            score=score,
            level=self.level_for_score(score),
            adjustments=[f"{len(findings)} finding(s) influenced aggregate scan risk."],
        )

    @staticmethod
    def level_for_score(score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"

