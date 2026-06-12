from pipeline.vulnerability_aggregator import VulnerabilityAggregator

class CollectStage:
    def __init__(self):
        self.aggregator = VulnerabilityAggregator()

    def execute(self, cve):
        return self.aggregator.aggregate(cve)