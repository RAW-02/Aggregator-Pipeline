from pipeline.vulnerability_aggregator import VulnerabilityAggregator

class CollectStage:
    def __init__(self):
        self.aggregator = VulnerabilityAggregator()

    def execute(self, cve):
        """
        Collect data from all collectors
        and build VulnerabilityRecord
        """
        return self.aggregator.aggregate(cve)