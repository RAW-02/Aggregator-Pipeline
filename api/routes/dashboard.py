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


@router.get("/severity-distribution")
def severity_distribution():

    result = search_service.severity_distribution()

    buckets = (
        result["aggregations"]
        ["severity_counts"]
        ["buckets"]
    )

    return {
        bucket["key"]: bucket["doc_count"]
        for bucket in buckets
    }