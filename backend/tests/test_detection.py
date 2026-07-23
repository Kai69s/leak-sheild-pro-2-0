from app.engines.detection import DetectionEngine
from app.engines.risk import RiskEngine


def test_detects_password_and_scores_high() -> None:
    secret = "ProdRootPass2026!"
    content = f"ENV=production\npassword='{secret}'\n"
    findings = DetectionEngine().scan(content)
    assert findings
    assert secret not in findings[0].context_snippet
    assert "[REDACTED]" in findings[0].context_snippet
    risk = RiskEngine().score_finding(findings[0], content, {})
    assert risk.level in {"HIGH", "CRITICAL"}


def test_finding_limit_prevents_unbounded_detection_work() -> None:
    content = "\n".join(f"password='UniqueProductionPassword{i:04d}!'" for i in range(400))
    findings = DetectionEngine().scan(content)

    assert len(findings) == 250

