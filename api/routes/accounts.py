"""Connected bounty account routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from api.database import get_session
from api.models import BountyAccount, BountyProgram
from api.agents.bounty_account_hub import account_hub

router = APIRouter(prefix="/accounts", tags=["bounty-account-hub"])


class AccountCreateRequest(BaseModel):
    platform: str = Field(default="hackerone", description="hackerone | bugcrowd | intigriti | yeswehack | custom")
    display_name: str
    username: Optional[str] = Field(default=None, description="Token identifier / API username / account label. Not a password.")
    token_secret: Optional[str] = Field(default=None, description="API token or OAuth bearer token. Never returned by API responses.")
    auth_type: Optional[str] = Field(default=None, description="api_token | oauth_bearer | basic_token | custom")
    api_base_url: Optional[str] = None
    notes: Optional[str] = None


class AccountTokenUpdateRequest(BaseModel):
    token_secret: str
    username: Optional[str] = None


class AccountSyncRequest(BaseModel):
    max_items: int = 200
    dry_run: bool = False


@router.get("/capabilities")
def capabilities():
    return {
        "name": "Bounty Account Hub",
        "login_method": "API/OAuth tokens only; raw platform passwords are not stored.",
        "platforms": account_hub.platform_defaults(),
        "can_do": [
            "connect HackerOne/Bugcrowd/Intigriti/YesWeHack/custom API accounts",
            "test token/API access",
            "sync private/invited programs where API permissions allow",
            "import synced program scope into Program Radar",
            "surface account/program sync events on LIVE dashboard",
            "detect expired/invalid tokens and permission failures",
            "automatically retry rate limits and temporary API outages",
            "preserve existing program data when a provider is unavailable",
            "let Architect Agent run 'sync bounty accounts' commands",
        ],
    }


@router.get("/")
def list_accounts(platform: Optional[str] = None, session: Session = Depends(get_session)):
    q = select(BountyAccount).order_by(BountyAccount.created_at.desc())
    if platform:
        q = select(BountyAccount).where(BountyAccount.platform == platform).order_by(BountyAccount.created_at.desc())
    return [account_hub.safe_account(a) for a in session.exec(q).all()]


@router.get("/snapshot")
def snapshot(session: Session = Depends(get_session)):
    accounts = session.exec(select(BountyAccount).order_by(BountyAccount.created_at.desc())).all()
    programs = session.exec(select(BountyProgram).order_by(BountyProgram.last_seen_at.desc())).all()
    connected_programs = []
    for p in programs:
        raw = p.scope_raw or ""
        if "connected_account_id" in raw:
            connected_programs.append(p)
    platforms = {}
    for a in accounts:
        platforms[a.platform] = platforms.get(a.platform, 0) + 1
    return {
        "total_accounts": len(accounts),
        "connected_accounts": len([a for a in accounts if a.status == "connected"]),
        "platforms": platforms,
        "connected_programs": len(connected_programs),
        "accounts": [account_hub.safe_account(a) for a in accounts[:20]],
        "recent_connected_programs": [p.model_dump(mode="json") for p in connected_programs[:30]],
    }


@router.post("/")
def create_account(req: AccountCreateRequest, session: Session = Depends(get_session)):
    try:
        account = account_hub.create_account(
            session,
            platform=req.platform,
            display_name=req.display_name,
            username=req.username,
            token_secret=req.token_secret,
            auth_type=req.auth_type,
            api_base_url=req.api_base_url,
            notes=req.notes,
        )
        return account_hub.safe_account(account)
    except Exception as exc:
        raise HTTPException(400, str(exc))


@router.get("/{account_id}")
def get_account(account_id: str, session: Session = Depends(get_session)):
    account = session.get(BountyAccount, account_id)
    if not account:
        raise HTTPException(404, "Account not found")
    return account_hub.safe_account(account)


@router.post("/{account_id}/token")
def update_token(account_id: str, req: AccountTokenUpdateRequest, session: Session = Depends(get_session)):
    account = session.get(BountyAccount, account_id)
    if not account:
        raise HTTPException(404, "Account not found")
    account = account_hub.update_token(session, account, req.token_secret, username=req.username)
    return account_hub.safe_account(account)


@router.post("/{account_id}/test")
def test_account(account_id: str, session: Session = Depends(get_session)):
    try:
        return account_hub.test_account(session, account_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.post("/{account_id}/sync")
def sync_account(account_id: str, req: AccountSyncRequest = AccountSyncRequest(), session: Session = Depends(get_session)):
    try:
        return account_hub.sync_account(session, account_id, dry_run=req.dry_run, max_items=max(1, min(req.max_items, 1000)))
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.post("/sync-all")
def sync_all(req: AccountSyncRequest = AccountSyncRequest(), session: Session = Depends(get_session)):
    try:
        return account_hub.sync_all_accounts(session, max_items=max(1, min(req.max_items, 1000)))
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.delete("/{account_id}")
def delete_account(account_id: str, session: Session = Depends(get_session)):
    account = session.get(BountyAccount, account_id)
    if not account:
        raise HTTPException(404, "Account not found")
    session.delete(account)
    session.commit()
    return {"ok": True, "deleted": account_id}
