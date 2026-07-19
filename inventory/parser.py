import csv
from pathlib import Path
from typing import List

from inventory.models import InventoryComponent


class InventoryParser:
    REQUIRED_COLUMNS = ["Host", "Vendor", "Product", "Version"]

    def parse(self, file_path: str) -> List[InventoryComponent]:
        file = Path(file_path)
        if not file.exists():
            raise FileNotFoundError(file_path)

        components = []
        with open(file, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            self.validate_columns(reader.fieldnames)

            for row in reader:
                version_val = row.get("Version") or ""
                component = InventoryComponent(
                    host=row["Host"].strip(),
                    vendor=row["Vendor"].strip().lower(),
                    product=row["Product"].strip().lower(),
                    version=version_val.strip(),
                    environment=row.get("Environment", "").strip(),
                    business_criticality=row.get("Criticality", "Medium").strip(),
                )

                components.append(component)

        return components

    def validate_columns(self, columns):
        if columns is None:
            raise ValueError("CSV has no header.")

        missing = []
        for column in self.REQUIRED_COLUMNS:
            if column not in columns:
                missing.append(column)

        if missing:
            raise ValueError(f"Missing required columns: {', '.join(missing)}")
