from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_session
from app.models import Scan
from app.schemas import ScanHistoryItem, ScanRequest, ScanResponse
from app.services.scan_service import ScanService

router = APIRouter()


@router.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanRequest, session: AsyncSession = Depends(get_session)) -> ScanResponse:
    return await ScanService(session).scan(payload)


@router.get("/scans", response_model=list[ScanHistoryItem])
async def list_scans(
    session: AsyncSession = Depends(get_session),
    risk_level: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
) -> list[ScanHistoryItem]:
    stmt = select(Scan).order_by(desc(Scan.created_at)).limit(limit)
    if risk_level:
        stmt = stmt.where(Scan.overall_level == risk_level.upper())
    if q:
        stmt = stmt.where(Scan.source_name.ilike(f"%{q}%"))
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)) -> ScanResponse:
    stmt = select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanService.to_response(scan, cache_hit=False)

