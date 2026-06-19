class EnrichmentStage:

    def execute(self, record):
        record.references = list(dict.fromkeys(record.references))
        record.github_aliases = list(dict.fromkeys(record.github_aliases))

        return record