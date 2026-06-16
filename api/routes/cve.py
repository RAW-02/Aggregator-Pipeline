from fastapi import APIRouter, HTTPException

from storage.search_service import SearchService

router = APIRouter(prefix="/cve", tags=["CVE"])

search_service = SearchService()

@router.get("/{cve_id}")
def get_cve(cve_id: str):
    result = search_service.get_vulnerability(cve_id)

    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")

    return result