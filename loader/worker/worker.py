from pipeline.initial_loader_pipeline import InitialLoadPipeline


class Worker:
    def __init__(self):
        self.pipeline = InitialLoadPipeline()

    def process(self, mitre_json):
        try:
            return self.pipeline.run(mitre_json), None

        except Exception as e:
            return None, e
