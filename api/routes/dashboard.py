from fastapi import APIRouter
from storage.search_service import SearchService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

search_service = SearchService()


@router.get("/summary")
def dashboard_summary():

    return search_service.dashboard_summary()


@router.get("/severity-distribution")
def severity_distribution():

    result = search_service.severity_distribution()

    buckets = result["aggregations"]["severity_counts"]["buckets"]

    return {bucket["key"]: bucket["doc_count"] for bucket in buckets}


@router.get("/top-products")
def top_products():

    result = search_service.top_products()

    buckets = result["aggregations"]["top_products"]["buckets"]

    return [
        {"product": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets
    ]


@router.get("/top-cwes")
def top_cwes():

    result = search_service.top_cwes()

    buckets = result["aggregations"]["top_cwes"]["buckets"]

    return [{"cwe": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]


@router.get("/top-threats")
def top_threats():

    result = search_service.dashboard_top_threats()

    return [
        {
            "cve_id": hit["_source"]["cve_id"],
            "threat_score": hit["_source"].get("threat_score", 0),
        }
        for hit in result["hits"]["hits"]
    ]


@router.get("/recent-cves")
def recent_cves():

    result = search_service.recent_cves()

    return [
        {
            "cve_id": hit["_source"]["cve_id"],
            "published_date": hit["_source"].get("published_date"),
            "severity": hit["_source"].get("severity"),
        }
        for hit in result["hits"]["hits"]
    ]
