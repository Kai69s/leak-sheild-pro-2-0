import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_client
from app.config import get_settings
from app.engines.detection import DetectionEngine
from app.engines.explanation import ExplanationEngine
from app.engines.risk import RiskEngine
from app.models import Finding, Scan
from app.schemas import Explanation, FindingResponse, ScanRequest, ScanResponse


class ScanService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.settings = get_settings()
        self.detector = DetectionEngine()
        self.risk_engine = RiskEngine()
        self.explainer = ExplanationEngine()

    async def scan(self, payload: ScanRequest) -> ScanResponse:
        if len(payload.content.encode("utf-8")) > self.settings.max_scan_bytes:
            raise HTTPException(status_code=413, detail="Scan payload exceeds configured size limit")

        content_hash = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()
        metadata_hash = hashlib.sha256(str(sorted(payload.metadata.items())).encode("utf-8")).hexdigest()
        cache_key = f"scan:{content_hash}:{metadata_hash}:{payload.source_name}"
        cached = await cache_client.get_json(cache_key)
        if cached:
            return ScanResponse(**cached, cache_hit=True)

        detections = self.detector.scan(payload.content)
        finding_models: list[Finding] = []
        finding_responses: list[FindingResponse] = []
        risk_results = []

        scan = Scan(
            source_name=payload.source_name,
            content_hash=content_hash,
            scan_metadata=payload.metadata,
        )
        self.session.add(scan)

        for detection in detections:
            risk = self.risk_engine.score_finding(detection, payload.content, payload.metadata)
            risk_results.append(risk)
            explanation = self.explainer.explain(detection, risk)
            model = Finding(
                scan=scan,
                rule_id=detection.rule.rule_id,
                secret_type=detection.rule.secret_type,
                severity=detection.rule.severity,
                risk_score=risk.score,
                risk_level=risk.level,
                value_hash=detection.value_hash,
                value_preview=detection.value_preview,
                line_number=detection.line_number,
                column_start=detection.column_start,
                column_end=detection.column_end,
                context_snippet=detection.context_snippet,
                explanation=explanation,
            )
            finding_models.append(model)
            finding_responses.append(self._finding_response(model, explanation))

        scan_risk = self.risk_engine.score_scan(risk_results)
        scan.overall_score = scan_risk.score
        scan.overall_level = scan_risk.level
        scan.finding_count = len(finding_models)
        self.session.add_all(finding_models)
        await self.session.commit()
        await self.session.refresh(scan)
        for model in finding_models:
            await self.session.refresh(model)

        response = self.to_response(scan, cache_hit=False)
        await cache_client.set_json(cache_key, response.model_dump(mode="json"))
        return response

    @classmethod
    def to_response(cls, scan: Scan, cache_hit: bool) -> ScanResponse:
        return ScanResponse(
            id=scan.id,
            source_name=scan.source_name,
            content_hash=scan.content_hash,
            overall_score=scan.overall_score,
            overall_level=scan.overall_level,
            finding_count=scan.finding_count,
            cache_hit=cache_hit,
            created_at=scan.created_at or datetime.now(timezone.utc),
            findings=[
                cls._finding_response(finding, finding.explanation)
                for finding in sorted(scan.findings, key=lambda item: (item.line_number, item.column_start))
            ],
        )

    @staticmethod
    def _finding_response(finding: Finding, explanation: dict) -> FindingResponse:
        return FindingResponse(
            id=finding.id,
            rule_id=finding.rule_id,
            secret_type=finding.secret_type,
            severity=finding.severity,
            risk_score=finding.risk_score,
            risk_level=finding.risk_level,
            value_hash=finding.value_hash,
            value_preview=finding.value_preview,
            line_number=finding.line_number,
            column_start=finding.column_start,
            column_end=finding.column_end,
            context_snippet=finding.context_snippet,
            explanation=Explanation(**explanation),
        )

