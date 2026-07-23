from datetime import datetime
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MAX_FILE_BYTES = 300_000
MAX_PROJECT_BYTES = 1_200_000
MAX_TEXT_BYTES = 420_000
MAX_METADATA_BYTES = 16_384


class ProjectFile(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=MAX_FILE_BYTES)
    size: int | None = Field(default=None, ge=0)


class ScanRequest(BaseModel):
    mode: Literal["text", "project-folder", "website"] = "text"
    content: str = ""
    source_name: str = Field(default="manual-input", max_length=255)
    website_url: str | None = Field(default=None, max_length=2048)
    url: str | None = Field(default=None, max_length=2048)
    files: list[ProjectFile] = Field(default_factory=list, max_length=140)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_name")
    @classmethod
    def safe_source_name(cls, value: str) -> str:
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
        if not cleaned:
            return "manual-input"
        return cleaned

    @model_validator(mode="after")
    def validate_scan_input(self) -> "ScanRequest":
        if self.mode == "website" and not (self.website_url or self.url):
            raise ValueError("website_url is required for website scans")
        if self.mode == "project-folder" and not self.files:
            raise ValueError("At least one project file is required")
        if self.mode == "text" and not self.content:
            raise ValueError("content is required for text scans")
        if self.mode == "text" and len(self.content.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError("Text scan exceeds the allowed size")
        if self.mode == "project-folder":
            total_bytes = sum(len(file.content.encode("utf-8")) for file in self.files)
            if total_bytes > MAX_PROJECT_BYTES:
                raise ValueError("Project scan exceeds the allowed total size")
        self.metadata.pop("client_session_id", None)
        if len(json.dumps(self.metadata, separators=(",", ":"), ensure_ascii=True).encode()) > MAX_METADATA_BYTES:
            raise ValueError("Scan metadata exceeds the allowed size")
        return self


class LearningGuide(BaseModel):
    definition: str
    why_dangerous: str
    attacker_method: str
    real_world_example: str
    business_impact: str
    common_mistakes: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    best_practices: list[str] = Field(default_factory=list)
    secure_coding: list[str] = Field(default_factory=list)
    prevention_checklist: list[str] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)


class DeveloperFixes(BaseModel):
    generic: str
    snippets: dict[str, str] = Field(default_factory=dict)


class Explanation(BaseModel):
    summary: str
    attacker_impact: str
    real_world_consequence: str
    remediation: str
    business_impact: str | None = None
    learning: LearningGuide | None = None
    developer_fixes: DeveloperFixes | None = None


class FindingResponse(BaseModel):
    id: str | None = None
    rule_id: str
    secret_type: str
    severity: str
    risk_score: float
    risk_level: str
    value_hash: str
    value_preview: str
    line_number: int
    column_start: int
    column_end: int
    context_snippet: str
    explanation: Explanation
    confidence: float | None = None
    file_path: str | None = None
    source_address: str | None = None
    public_accessible: bool = False
    owasp: str | None = None
    cwe: str | None = None
    capec: str | None = None


class ScanResponse(BaseModel):
    id: str | None = None
    source_name: str
    content_hash: str
    overall_score: float
    overall_level: str
    finding_count: int
    cache_hit: bool = False
    created_at: datetime | None = None
    findings: list[FindingResponse]
    mode: str = "text"
    security_score: float | None = None
    grade: str | None = None
    public_exposure_count: int = 0
    scanned_files: int = 1
    scanned_addresses: list[str] = Field(default_factory=list)
    skipped_addresses: list[str] = Field(default_factory=list)
    recommendation: dict[str, Any] | None = None
    advisor: dict[str, Any] | None = None
    assessment: dict[str, Any] | None = None
    roadmap: list[dict[str, Any]] = Field(default_factory=list)
    comparison: dict[str, Any] | None = None


class ScanHistoryItem(BaseModel):
    id: str
    source_name: str
    overall_score: float
    overall_level: str
    finding_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

