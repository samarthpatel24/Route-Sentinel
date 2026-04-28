"""Test fixture: Route file with NO authentication on any endpoint."""
from fastapi import APIRouter

router = APIRouter(prefix="/database")


@router.get("/tables")
async def list_tables():
    return {"tables": ["users", "sessions"]}


@router.get("/tables/{table_name}/data")
async def get_table_data(table_name: str, page: int = 1, page_size: int = 50):
    return {"table": table_name, "data": []}


@router.post("/query")
async def execute_query(query: str):
    return {"result": []}


@router.delete("/tables/{table_name}")
async def drop_table(table_name: str):
    return {"deleted": table_name}
