from pipeline.aggregation_pipeline import AggregationPipeline
from pipeline.stages.refresh_collect import RefreshCollectStage
from pipeline.stages.entichment import EnrichmentStage
from pipeline.stages.score import ThreatScoreStage
from pipeline.stages.validate import ValidationStage
from pipeline.stages.store import StorageStage


class RefreshPipeline:
    def __init__(self):
        self.aggregate = AggregationPipeline()
        self.collect = RefreshCollectStage()
        self.enrich = EnrichmentStage()
        self.score = ThreatScoreStage()
        self.validate = ValidationStage()
        self.store = StorageStage()

    def run(self, cve):
        response = self.collect.execute(cve)

        if response["status"] == "create":
            print(f"{cve} not found locally.")
            print("Creating new record...")
            return self.aggregate.run(cve)

        record = response["record"]
        record = self.enrich.execute(record)
        record = self.score.execute(record)
        record = self.validate.execute(record)
        self.store.execute(record)

        print(f"{cve} refreshed successfully")
        return record