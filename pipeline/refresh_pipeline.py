from pipeline.stages.refresh_collect import RefreshCollectStage
from pipeline.stages.entichment import EnrichmentStage
from pipeline.stages.score import ThreatScoreStage
from pipeline.stages.validate import ValidationStage
from pipeline.stages.store import StorageStage


class RefreshPipeline:
    def __init__(self):
        self.collect = RefreshCollectStage()
        self.enrich = EnrichmentStage()
        self.score = ThreatScoreStage()
        self.validate = ValidationStage()
        self.store = StorageStage()

    def run(self, cve):
        record = self.collect.execute(cve)
        if record is None:
            return None

        record = self.enrich.execute(record)
        record = self.score.execute(record)
        record = self.validate.execute(record)
        self.store.execute(record)
        return record