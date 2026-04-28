"""Test fixture: Some endpoints protected, some not."""
from fastapi import APIRouter, Depends


def get_current_user():
    pass


def require_roles(*roles):
    pass


router = APIRouter(prefix="/consent")


@router.get("/status")
async def get_consent_status():
    return {"status": "unknown"}


@router.put("/update")
async def update_consent(current_user: dict = Depends(get_current_user)):
    return {"updated": True}


@router.get("/history")
async def get_consent_history():
    return {"history": []}


@router.delete("/revoke")
async def revoke_consent(current_user: dict = Depends(require_roles("admin"))):
    return {"revoked": True}
