from fastapi import APIRouter

import math

from api.services.query_resolver import QueryResolver

router = APIRouter()

resolver = QueryResolver()



@router.get("/search")
def search(
    query: str,
    page: int = 1,
    size: int = 20,
    sort: str | None = None
):

    result = resolver.resolve(
        query,
        page,
        size,
        sort
    )

    hits = result["hits"]["hits"]

    total = result["hits"]["total"]["value"]

    return {
    "query": query,
    "page": page,
    "size": size,
    "sort": sort,
    "total": total,
    "total_pages": math.ceil(total / size),
    "count": len(hits),
    "results": [
        hit["_source"]
        for hit in hits
    ]
}



def search_with_filters(
    self,
    filters,
    page=1,
    size=20
):

    must = []

    if filters.get("severity"):
        must.append({
            "term": {
                "severity": filters["severity"]
            }
        })

    if filters.get("kev") is not None:
        must.append({
            "term": {
                "kev_status": filters["kev"]
            }
        })

    if filters.get("exploit") is not None:
        must.append({
            "term": {
                "exploit_available": filters["exploit"]
            }
        })

    if filters.get("cwe"):
        must.append({
            "match": {
                "cwe": filters["cwe"]
            }
        })

    query = {
        "query": {
            "bool": {
                "must": must
            }
        }
    }

    return self._execute_search(
        query,
        page,
        size
    )