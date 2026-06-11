from fastapi import APIRouter

from api.services.query_resolver import QueryResolver

router = APIRouter()

resolver = QueryResolver()



@router.get("/search")
def search(
    query: str,
    page: int = 1,
    size: int = 20
):

    result = resolver.resolve(
        query,
        page,
        size
    )

    hits = result["hits"]["hits"]

    total = result["hits"]["total"]["value"]

    return {
        "query": query,
        "page": page,
        "size": size,
        "total": total,
        "count": len(hits),
        "results": [
            hit["_source"]
            for hit in hits
        ]
    }