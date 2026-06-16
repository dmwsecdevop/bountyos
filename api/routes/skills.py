from fastapi import APIRouter, HTTPException
from api.services import skill_registry as reg
router=APIRouter(prefix="/skills", tags=["skills"])
@router.get("/")
def all_skills(): return reg.all_skills()
@router.get("/categories")
def categories(): return reg.categories()
@router.get("/passive")
def passive(): return reg.passive_skills()
@router.get("/approval-required")
def approval(): return reg.approval_required_skills()
@router.get("/{name}")
def get(name: str):
    skill=reg.get_skill(name)
    if not skill: raise HTTPException(404,"Skill not found")
    return skill
