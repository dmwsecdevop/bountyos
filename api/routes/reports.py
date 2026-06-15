from fastapi import APIRouter, HTTPException, Query
from api.services import report_builder as rb
router=APIRouter(prefix="/reports", tags=["reports"])
@router.get("/templates")
def templates(): return rb.templates()
@router.post("/finding/{finding_id}/draft")
def draft(finding_id: str, template: str = Query("Generic Markdown")):
    report=rb.draft_finding_report(finding_id, template)
    if not report: raise HTTPException(404,"Finding not found")
    return report
@router.post("/scan/{scan_id}/summary")
def summary(scan_id: str): return rb.scan_summary(scan_id)
