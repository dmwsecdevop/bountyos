import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from api.database import get_session, session_ctx
from api.services.mobile_apk import APKAnalysis, capabilities
router=APIRouter(prefix="/mobile", tags=["mobile-apk"])
class APKIn(BaseModel):
    filename: str; package_name: str|None=None; min_sdk: str|None=None; target_sdk: str|None=None; permissions: list[str]=[]; exported_components: list[str]=[]; findings: list[str]=[]
@router.get("/capabilities")
def caps(): return capabilities()
@router.get("/analyses")
def analyses(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(APKAnalysis)).all()]
@router.post("/apk/metadata")
def meta(body: APKIn):
    with session_ctx() as s:
        row=APKAnalysis(filename=body.filename,package_name=body.package_name,min_sdk=body.min_sdk,target_sdk=body.target_sdk,permissions=json.dumps(body.permissions),exported_components=json.dumps(body.exported_components),findings=json.dumps(body.findings)); s.add(row); s.commit(); s.refresh(row); return row.model_dump()
@router.get("/analyses/{analysis_id}")
def get(analysis_id: str, session: Session=Depends(get_session)):
    row=session.get(APKAnalysis, analysis_id)
    if not row: raise HTTPException(404,"Analysis not found")
    return row.model_dump()
