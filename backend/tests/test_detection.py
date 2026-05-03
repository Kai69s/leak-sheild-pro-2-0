from app.engines.detection import DetectionEngine
from app.engines.risk import RiskEngine


def test_detects_password_and_scores_high() -> None:
    content = "ENV=production\npassword='ProdRootPass2026!'\n"
    findings = DetectionEngine().scan(content)
    assert findings
    risk = RiskEngine().score_finding(findings[0], content, {})
    assert risk.level in {"HIGH", "CRITICAL"}

