from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_name: Mapped[str] = mapped_column(String(255), default="manual-input")
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    overall_score: Mapped[float] = mapped_column(Float, default=0)
    overall_level: Mapped[str] = mapped_column(String(20), default="LOW", index=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    scan_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(100), index=True)
    secret_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    value_preview: Mapped[str] = mapped_column(String(120))
    line_number: Mapped[int] = mapped_column(Integer)
    column_start: Mapped[int] = mapped_column(Integer)
    column_end: Mapped[int] = mapped_column(Integer)
    context_snippet: Mapped[str] = mapped_column(Text)
    explanation: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="findings")

