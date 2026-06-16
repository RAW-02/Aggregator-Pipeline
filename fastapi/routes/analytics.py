from fastapi import APIRouter

from storage.search_service import SearchService

router = APIRouter(
    prefix="/api/analytics",
    tags=["Analytics"]
)

search_service = SearchService()


@router.get("/summary")
def get_summary():

    total = search_service.es.count(
        index=search_service.index_name
    )["count"]

    critical = search_service.es.count(
        index=search_service.index_name,
        body={
            "query": {
                "term": {
                    "severity": "CRITICAL"
                }
            }
        }
    )["count"]

    high = search_service.es.count(
        index=search_service.index_name,
        body={
            "query": {
                "term": {
                    "severity": "HIGH"
                }
            }
        }
    )["count"]

    kev = search_service.es.count(
        index=search_service.index_name,
        body={
            "query": {
                "term": {
                    "kev_status": True
                }
            }
        }
    )["count"]

    exploitable = search_service.es.count(
        index=search_service.index_name,
        body={
            "query": {
                "term": {
                    "exploit_available": True
                }
            }
        }
    )["count"]

    return {
        "total_vulnerabilities": total,
        "critical": critical,
        "high": high,
        "kev": kev,
        "exploitable": exploitable
    }



@router.get("/severity")
def severity_distribution():

    result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "severity_distribution": {
                    "terms": {
                        "field": "severity",
                        "size": 10
                    }
                }
            }
        }
    )

    buckets = result[
        "aggregations"
    ][
        "severity_distribution"
    ][
        "buckets"
    ]

    return [
        {
            "severity": bucket["key"],
            "count": bucket["doc_count"]
        }
        for bucket in buckets
    ]



@router.get("/dashboard")
def dashboard():

    total = search_service.es.count(
        index=search_service.index_name
    )

    severity_result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "severity": {
                    "terms": {
                        "field": "severity"
                    }
                }
            }
        }
    )

    cwe_result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "top_cwe": {
                    "terms": {
                        "field": "cwe",
                        "size": 5
                    }
                }
            }
        }
    )

    epss_result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "avg_epss": {
                    "avg": {
                        "field": "epss_score"
                    }
                }
            }
        }
    )

    threat_result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "avg_threat": {
                    "avg": {
                        "field": "threat_score"
                    }
                }
            }
        }
    )

    return {

        "total_vulnerabilities":
            total["count"],

        "average_epss":
            epss_result["aggregations"]["avg_epss"]["value"],

        "average_threat_score":
            threat_result["aggregations"]["avg_threat"]["value"],

        "severity_distribution":
            severity_result["aggregations"]["severity"]["buckets"],

        "top_cwe":
            cwe_result["aggregations"]["top_cwe"]["buckets"]
    }


@router.get("/epss")
def epss_stats():

    result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "avg_epss": {
                    "avg": {
                        "field": "epss_score"
                    }
                },
                "max_epss": {
                    "max": {
                        "field": "epss_score"
                    }
                },
                "min_epss": {
                    "min": {
                        "field": "epss_score"
                    }
                }
            }
        }
    )

    return {
        "average":
            result["aggregations"]["avg_epss"]["value"],

        "maximum":
            result["aggregations"]["max_epss"]["value"],

        "minimum":
            result["aggregations"]["min_epss"]["value"]
    }



@router.get("/threat-score")
def threat_score_stats():

    result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "avg_threat": {
                    "avg": {
                        "field": "threat_score"
                    }
                },
                "max_threat": {
                    "max": {
                        "field": "threat_score"
                    }
                },
                "min_threat": {
                    "min": {
                        "field": "threat_score"
                    }
                }
            }
        }
    )

    return {
        "average":
            result["aggregations"]["avg_threat"]["value"],

        "maximum":
            result["aggregations"]["max_threat"]["value"],

        "minimum":
            result["aggregations"]["min_threat"]["value"]
    }



@router.get("/top-cwe")
def top_cwe():

    result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "top_cwe": {
                    "terms": {
                        "field": "cwe",
                        "size": 10
                    }
                }
            }
        }
    )

    buckets = result[
        "aggregations"
    ][
        "top_cwe"
    ][
        "buckets"
    ]

    return [
        {
            "cwe": bucket["key"],
            "count": bucket["doc_count"]
        }
        for bucket in buckets
    ]




@router.get("/vendors")
def top_vendors():

    result = search_service.es.search(
        index=search_service.index_name,
        size=0,
        body={
            "aggs": {
                "top_products": {
                    "terms": {
                        "field": "products.keyword",
                        "size": 1000
                    }
                }
            }
        }
    )

    buckets = result["aggregations"]["top_products"]["buckets"]

    vendor_count = {}

    for bucket in buckets:

        product = bucket["key"]

        if ":" in product:
            vendor = product.split(":")[0]
        else:
            vendor = product

        vendor_count[vendor] = (
            vendor_count.get(vendor, 0)
            + bucket["doc_count"]
        )

    vendors = sorted(
        vendor_count.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [
        {
            "vendor": vendor,
            "count": count
        }
        for vendor, count in vendors[:20]
    ]