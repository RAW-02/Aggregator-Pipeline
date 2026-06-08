from resolver.alias_resolver import AliasResolver
from resolver.product_resolver import ProductResolver

class KeywordResolver:
    def __init__(self):
        self.product = ProductResolver()
        self.alias = AliasResolver()

    def resolve(self, query):
        results = []
        results.extend(
            self.product.resolve(query)

        )
        results.extend(
            self.alias.resolve(query)
        )

        return results
    

    