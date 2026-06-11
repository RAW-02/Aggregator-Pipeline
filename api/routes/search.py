from fastapi import APIRouter

from api.services.query_resolver import QueryResolver

router = APIRouter()

resolver = QueryResolver()


@router.get("/search")
def search(query: str):

    result = resolver.resolve(query)

    hits = result["hits"]["hits"]

    return {
        "query": query,
        "count": len(hits),
        "results": [

            hit["_source"]

            for hit in hits

        ]
    }