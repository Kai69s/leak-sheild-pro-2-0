from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    content: str = Field(min_length=1)
    source_name: str = Field(default="manual-input", max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Explanation(BaseModel):
    summary: str
    attacker_impact: str
    real_world_consequence: str
    remediation: str


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


class ScanHistoryItem(BaseModel):
    id: str
    source_name: str
    overall_score: float
    overall_level: str
    finding_count: int
    created_at: datetime

    class Config:
        from_attributes = True

