from fastapi import APIRouter
from storage.search_service import SearchService

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

search_service = SearchService()


@router.get("/summary")
def dashboard_summary():

    return search_service.dashboard_summary()