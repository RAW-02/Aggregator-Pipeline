from pipeline.threat_score import ThreatScoreCalculator

class ThreatScoreStage:

    def execute(self, record):
        record.threat_score = ThreatScoreCalculator.calculate(record)
        return record