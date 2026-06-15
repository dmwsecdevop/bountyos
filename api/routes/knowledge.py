from fastapi import APIRouter
from pydantic import BaseModel
from api.services import knowledge_graph as kg
router=APIRouter(prefix="/knowledge", tags=["knowledge"])
class Attempt(BaseModel):
    technology: str; technique: str; success: bool=False; false_positive: bool=False; cvss: float|None=None; payload: str|None=None; target: str|None=None; notes: str|None=None
class Chain(BaseModel):
    from_id: str; to_id: str; chain_title: str; combined_severity: str="medium"
class Tech(BaseModel): technology: str|None=None; limit: int=10
@router.get("/stats")
def stats(): return kg.stats()
@router.post("/attempt")
def attempt(a: Attempt): return kg.record_attempt(**a.model_dump()).model_dump()
@router.post("/chain")
def chain(c: Chain): return kg.record_chain(**c.model_dump()).model_dump()
@router.post("/best-approaches")
def best(t: Tech): return kg.best_approaches(t.technology, t.limit)
@router.post("/agent-context")
def ctx(t: Tech): return kg.get_agent_context(t.technology)
