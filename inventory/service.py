from inventory.models import InventoryReport
from inventory.parser import InventoryParser
from inventory.matcher import InventoryMatcher
from inventory.assessment import RiskAssessment


class InventoryService:

    def __init__(
        self,
        parser: InventoryParser,
        matcher: InventoryMatcher,
        assessment: RiskAssessment,
    ):
        self.parser = parser
        self.matcher = matcher
        self.assessment = assessment

    def analyze(self, csv_file: str) -> InventoryReport:
        try:
            components = self.parser.parse(csv_file)
            reports = [self.matcher.match(component) for component in components]

            summary = self.assessment.calculate(reports)
            return InventoryReport(summary=summary, components=reports)

        except Exception as ex:
            raise RuntimeError(f"Inventory analysis failed: {ex}")
