from pipeline.stages.collect import CollectStage
from pipeline.stages.entichment import EnrichmentStage
from pipeline.stages.score import ThreatScoreStage
from pipeline.stages.validate import ValidationStage
from pipeline.stages.store import StorageStage


class AggregationPipeline:

    def __init__(self):
        self.collect = CollectStage()
        self.enrich = EnrichmentStage()
        self.score = ThreatScoreStage()
        self.validate = ValidationStage()
        self.store = StorageStage()

    def run(self, cve):
        record = self.collect.execute(cve)
        record = self.enrich.execute(record)
        record = self.score.execute(record)
        record = self.validate.execute(record)
        self.store.execute(record)
        return record