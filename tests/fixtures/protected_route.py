"""Test fixture: Route file with Depends(get_current_user) on every endpoint."""
from fastapi import APIRouter, Depends


def get_current_user():
    pass


router = APIRouter(prefix="/admin")


@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    return {"users": []}


@router.post("/users")
async def create_user(current_user: dict = Depends(get_current_user)):
    return {"created": True}


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    return {"deleted": user_id}
