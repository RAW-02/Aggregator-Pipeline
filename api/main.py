
from fastapi import FastAPI

from api.routes.search import router as search_router
from api.routes.dashboard import router as dashboard_router

app = FastAPI(
    title="CVE Threat Intelligence API",
    version="1.0"
)

app.include_router(search_router)
app.include_router(dashboard_router)