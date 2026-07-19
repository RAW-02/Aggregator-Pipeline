from fastapi import APIRouter, UploadFile, File
import shutil
import os
from dataclasses import asdict
from inventory.service import InventoryService
from inventory.parser import InventoryParser
from inventory.matcher import InventoryMatcher
from inventory.assessment import RiskAssessment

from storage.search_service import SearchService

router = APIRouter(prefix="/inventory", tags=["Inventory"])

service = InventoryService(
    parser=InventoryParser(),
    matcher=InventoryMatcher(SearchService()),
    assessment=RiskAssessment(),
)


@router.post("/analyze")
async def analyze_inventory(file: UploadFile = File(...)):

    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    report = service.analyze(file_path)

    return asdict(report)
