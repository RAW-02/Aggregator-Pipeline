from loader.pipeline.mitre_initial_pipeline import MitreInitialPipeline


class MitreWorker:
    def __init__(self):
        self.pipeline = MitreInitialPipeline()

    def process(self, mitre_json):
        print(type(mitre_json))
        try:
            return self.pipeline.run(mitre_json), None

        except Exception as e:
            return None, e
