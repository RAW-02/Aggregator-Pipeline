from pipeline.vulnerability_aggregator import VulnerabilityAggregator

class InitialLoadPipeline:
    def __init__(self):
        self.aggregator = VulnerabilityAggregator()

    def run(self, mitre_json):
        return self.aggregator.aggregate_from_mitre_json(mitre_json)