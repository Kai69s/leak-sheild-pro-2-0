import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.cache import cache_client
from app.config import get_settings
from app.engines.assessment import WebsiteAssessmentEngine
from app.engines.detection import DetectionEngine
from app.engines.education import mapping_for
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
        self.website_engine = WebsiteAssessmentEngine()

    async def scan(self, payload: ScanRequest) -> ScanResponse:
        if payload.mode == "website":
            assessment = await self.website_engine.assess(payload.website_url or payload.url or "")
            return await self._persist_assessment(payload, assessment)

        content, file_ranges = self._scan_content(payload)
        if len(content.encode("utf-8")) > self.settings.max_scan_bytes * 5:
            raise HTTPException(status_code=413, detail="Scan payload exceeds configured size limit")

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        metadata_hash = hashlib.sha256(str(sorted(payload.metadata.items())).encode("utf-8")).hexdigest()
        cache_key = f"scan:{payload.mode}:{content_hash}:{metadata_hash}:{payload.source_name}"
        cached = await cache_client.get_json(cache_key)
        if cached:
            cached["cache_hit"] = True
            return ScanResponse(**cached)

        detections = self.detector.scan(content)
        finding_models: list[Finding] = []
        risk_results = []

        scan = Scan(
            source_name=payload.source_name,
            content_hash=content_hash,
            scan_metadata={**payload.metadata, "mode": payload.mode, "scanned_files": max(1, len(payload.files))},
        )
        self.session.add(scan)

        for detection in detections:
            risk = self.risk_engine.score_finding(detection, content, payload.metadata)
            risk_results.append(risk)
            explanation = self.explainer.explain(detection, risk)
            file_path = self._file_for_line(detection.line_number, file_ranges)
            if file_path:
                explanation["_finding"] = {"file_path": file_path}
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

    @staticmethod
    def _scan_content(payload: ScanRequest) -> tuple[str, list[tuple[int, int, str]]]:
        if payload.mode != "project-folder":
            return payload.content, []
        chunks = []
        ranges = []
        current_line = 1
        for file in payload.files:
            marker = f"// FILE: {file.path}\n"
            chunk = f"{marker}{file.content}\n"
            line_count = chunk.count("\n") + 1
            ranges.append((current_line, current_line + line_count, file.path))
            chunks.append(chunk)
            current_line += line_count
        return "\n".join(chunks), ranges

    @staticmethod
    def _file_for_line(line: int, ranges: list[tuple[int, int, str]]) -> str | None:
        return next((path for start, end, path in ranges if start <= line <= end), None)

    async def _persist_assessment(self, payload: ScanRequest, result: dict[str, Any]) -> ScanResponse:
        previous_result = await self.session.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(Scan.source_name == result["source_name"])
            .order_by(desc(Scan.created_at))
            .limit(1)
        )
        previous = previous_result.scalar_one_or_none()
        previous_rules = {finding.rule_id for finding in previous.findings} if previous else set()
        current_rules = {item["rule_id"] for item in result["findings"]}
        result["comparison"] = {
            "has_previous": previous is not None,
            "new_findings": sorted(current_rules - previous_rules),
            "fixed_findings": sorted(previous_rules - current_rules),
            "risk_change": round(result["overall_score"] - (previous.overall_score if previous else 0), 1),
            "previous_score": previous.overall_score if previous else None,
        }
        rich_keys = (
            "mode",
            "security_score",
            "grade",
            "public_exposure_count",
            "scanned_files",
            "scanned_addresses",
            "skipped_addresses",
            "recommendation",
            "advisor",
            "assessment",
            "roadmap",
            "comparison",
        )
        scan = Scan(
            source_name=result["source_name"],
            content_hash=result["content_hash"],
            overall_score=result["overall_score"],
            overall_level=result["overall_level"],
            finding_count=result["finding_count"],
            scan_metadata={**payload.metadata, "mode": payload.mode, "_result": {key: result.get(key) for key in rich_keys}},
        )
        self.session.add(scan)
        for item in result["findings"]:
            explanation = {**item["explanation"]}
            explanation["_finding"] = {
                key: item.get(key)
                for key in ("confidence", "file_path", "source_address", "public_accessible", "owasp", "cwe", "capec")
            }
            self.session.add(
                Finding(
                    scan=scan,
                    rule_id=item["rule_id"],
                    secret_type=item["secret_type"],
                    severity=item["severity"],
                    risk_score=item["risk_score"],
                    risk_level=item["risk_level"],
                    value_hash=item["value_hash"],
                    value_preview=item["value_preview"],
                    line_number=item["line_number"],
                    column_start=item["column_start"],
                    column_end=item["column_end"],
                    context_snippet=item["context_snippet"],
                    explanation=explanation,
                )
            )
        await self.session.commit()
        await self.session.refresh(scan)
        result.update({"id": scan.id, "created_at": scan.created_at or datetime.now(timezone.utc), "cache_hit": False})
        response = ScanResponse(**result)
        await cache_client.set_json(f"website:{result['content_hash']}", response.model_dump(mode="json"), ttl=900)
        return response

    @classmethod
    def to_response(cls, scan: Scan, cache_hit: bool) -> ScanResponse:
        result_metadata = dict(scan.scan_metadata.get("_result", {})) if scan.scan_metadata else {}
        mode = result_metadata.pop("mode", scan.scan_metadata.get("mode", "text") if scan.scan_metadata else "text")
        scanned_files = result_metadata.pop(
            "scanned_files", scan.scan_metadata.get("scanned_files", 1) if scan.scan_metadata else 1
        )
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
            mode=mode,
            scanned_files=scanned_files,
            **result_metadata,
        )

    @staticmethod
    def _finding_response(finding: Finding, explanation: dict) -> FindingResponse:
        finding_metadata = explanation.get("_finding", {})
        clean_explanation = {key: value for key, value in explanation.items() if not key.startswith("_")}
        owasp, cwe, capec = mapping_for("secrets")
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
            explanation=Explanation(**clean_explanation),
            confidence=finding_metadata.get("confidence"),
            file_path=finding_metadata.get("file_path"),
            source_address=finding_metadata.get("source_address"),
            public_accessible=finding_metadata.get("public_accessible", False),
            owasp=finding_metadata.get("owasp", owasp),
            cwe=finding_metadata.get("cwe", cwe),
            capec=finding_metadata.get("capec", capec),
        )

