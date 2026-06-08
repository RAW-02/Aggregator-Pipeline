from resolver.input_classifier import InputClassifier
from resolver.cve_resolver import CVEResolver
from resolver.keyword_resolver import KeywordResolver
from resolver.input_classifier import InputClassifier
from resolver.cve_resolver import CVEResolver
from resolver.keyword_resolver import KeywordResolver
from resolver.ranking_resolver import RankingResolver

class InputResolver:
    def __init__(self):
        self.keyword = KeywordResolver()

    def resolve(self, query):
        print("Input resolving ....")
        
        query_type = InputClassifier.classify(query)
        if query_type == "cve":
            return CVEResolver.resolve(query)

        candidates = self.keyword.resolve(query)

        candidates = RankingResolver.rank(candidates)

        return candidates