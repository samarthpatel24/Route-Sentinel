"""Test fixture: Auth applied at the router level via dependencies kwarg."""
from fastapi import APIRouter, Depends


def get_current_user():
    pass


router = APIRouter(
    prefix="/monitoring",
    dependencies=[Depends(get_current_user)],
)


@router.get("/dashboard")
async def get_dashboard():
    return {"metrics": []}


@router.get("/alerts")
async def get_alerts():
    return {"alerts": []}


@router.post("/alerts")
async def create_alert(name: str):
    return {"created": name}
