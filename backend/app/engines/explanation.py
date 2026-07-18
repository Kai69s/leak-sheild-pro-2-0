from app.engines.detection.scanner import DetectionFinding
from app.engines.education import developer_fixes, learning_guide
from app.engines.risk import RiskResult


class ExplanationEngine:
    def explain(self, finding: DetectionFinding, risk: RiskResult) -> dict:
        adjustment_text = " ".join(risk.adjustments) if risk.adjustments else "No contextual adjustment was applied."
        return {
            "summary": f"{finding.rule.description} Classified as {risk.level} with score {risk.score}/100.",
            "attacker_impact": f"{finding.rule.attacker_impact} {adjustment_text}",
            "real_world_consequence": finding.rule.consequence,
            "remediation": finding.rule.remediation,
            "business_impact": finding.rule.consequence,
            "learning": learning_guide(
                finding.rule.secret_type,
                "secrets",
                finding.rule.consequence,
                finding.rule.remediation,
            ),
            "developer_fixes": developer_fixes(),
        }

