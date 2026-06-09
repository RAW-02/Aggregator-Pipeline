from pipeline.threat_score import ThreatScore

class ThreatScoreStage:

    def execute(self, record):
        record.threat_score = ThreatScore.calculate(record)
        return record