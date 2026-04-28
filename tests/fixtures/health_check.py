"""Test fixture: Legitimate public endpoints that should be allowlisted."""
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.get("/docs")
async def docs():
    return {"docs": "openapi"}
