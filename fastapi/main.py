from fastapi import FastAPI
from fastapi.routes.search import router as search_router
from fastapi.routes.dashboard import router as dashboard_router
from fastapi.routes.export import router as export_router

from fastapi.routes.vulnerability import router as vulnerability_router
from fastapi.routes.cve import router as cve_router
from fastapi.routes.analytics import router as analytics_router

from fastapi.routes.vulnerability import router as vulnerability_router

app = FastAPI(
    title="CVE Threat Intelligence API",
    version="1.0"
)

app.include_router(search_router)
app.include_router(dashboard_router)

app.include_router(cve_router)

app.include_router(export_router)

app.include_router(vulnerability_router)

app.include_router(analytics_router)