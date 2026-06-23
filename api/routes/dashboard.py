



from datetime import datetime, timedelta, timezone
from fastapi import APIRouter
from storage.search_service import SearchService
from storage.elasticsearch_client import ElasticsearchClient

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

search_service = SearchService()

# ── Helpers ────────────────────────────────────────────────────

def _safe_score(value, default=None):
    """Return None instead of 0.0 so the frontend knows the score wasn't computed yet."""
    if value is None:
        return default
    try:
        f = float(value)
        return f if f > 0 else default   # 0.0 == not yet scored
    except (TypeError, ValueError):
        return default


# ── Existing endpoints (unchanged) ────────────────────────────

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
        {"product": bucket["key"], "count": bucket["doc_count"]}
        for bucket in buckets
    ]


@router.get("/top-cwes")
def top_cwes():
    result = search_service.top_cwes()
    buckets = result["aggregations"]["top_cwes"]["buckets"]
    return [
        {"cwe": bucket["key"], "count": bucket["doc_count"]}
        for bucket in buckets
    ]


@router.get("/top-threats")
def top_threats():
    result = search_service.dashboard_top_threats()
    return [
        {
            "cve_id": hit["_source"]["cve_id"],
            "threat_score": hit["_source"].get("threat_score", 0)
        }
        for hit in result["hits"]["hits"]
    ]


# ── Fixed: /recent-cves now returns all fields the frontend needs ──

@router.get("/recent-cves")
def recent_cves():
    """
    Returns recent CVEs with all fields required by the dashboard:
    cve_id, severity, published_date, threat_score, kev_status, epss_score.

    Previously only cve_id + severity + published_date were returned —
    that's why the CVE Intelligence Feed showed N/A for threat score
    and the KEV Watchlist was always empty.
    """
    result = search_service.recent_cves()

    return [
        {
            "cve_id":         src.get("cve_id"),
            "published_date": src.get("published_date"),
            "severity":       src.get("severity"),

            # threat_score: return None instead of 0.0 (0.0 = not yet scored)
            "threat_score":   _safe_score(src.get("threat_score")),

            # kev_status: stored as bool; default False
            "kev_status":     bool(src.get("kev_status", False)),

            # epss_score: 0–1 probability; return None when absent
            "epss_score":     _safe_score(src.get("epss_score")),
        }
        for hit in result["hits"]["hits"]
        for src in [hit["_source"]]   # unpack once, reuse cleanly
    ]


# ── New: /trend — 7-day CVE count histogram ────────────────────

@router.get("/trend")
def trend_data():
    """
    Returns CVE counts grouped by day for the last 7 days.
    Uses a date_histogram aggregation on published_date.

    If your CVEs were published years ago the counts will be 0 for
    recent days (which is correct — no new CVEs were published then).
    The frontend handles this gracefully.
    """
    es = ElasticsearchClient().get_client()

    # Build the last 7 calendar days (today included)
    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]

    query = {
        "size": 0,
        "query": {
            "range": {
                "published_date": {
                    "gte": days[0].isoformat(),   # 6 days ago
                    "lte": days[-1].isoformat()   # today
                }
            }
        },
        "aggs": {
            "daily_counts": {
                "date_histogram": {
                    "field":             "published_date",
                    "calendar_interval": "day",
                    "format":            "yyyy-MM-dd",
                    "min_doc_count":     0,
                    "extended_bounds": {
                        "min": days[0].isoformat(),
                        "max": days[-1].isoformat()
                    }
                }
            }
        }
    }

    try:
        result = es.search(index="vulnerabilities", body=query)
        buckets = result["aggregations"]["daily_counts"]["buckets"]

        return [
            {
                # Short weekday label for the chart x-axis
                "day":   datetime.strptime(b["key_as_string"], "%Y-%m-%d")
                                 .strftime("%a"),          # "Mon", "Tue" …
                "date":  b["key_as_string"],
                "count": b["doc_count"]
            }
            for b in buckets
        ]

    except Exception as e:
        # Return empty list — frontend shows "No trend data yet" gracefully
        print(f"[dashboard/trend] aggregation error: {e}")
        return []
