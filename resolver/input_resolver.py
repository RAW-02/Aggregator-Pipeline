from resolver.input_classifier import InputClassifier
from resolver.cve_resolver import CVEResolver
from resolver.keyword_resolver import KeywordResolver


class InputResolver:
    def __init__(self):
        self.keyword = KeywordResolver()

    def resolve(self, user_input):
        print("Resolving user input ..........")
        input_type = InputClassifier.classify(user_input)
        
        if input_type == "cve":
            return CVEResolver.resolve(user_input)

        return self.keyword.resolve(user_input)