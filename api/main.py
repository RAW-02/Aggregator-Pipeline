from fastapi import FastAPI

from api.routes.search import router as search_router

app = FastAPI(
    title="CVE Threat Intelligence API",
    version="1.0"
)

app.include_router(search_router)