class AliasResolver:
    def __init__(self, alias_db):
        self.alias_db = alias_db

    def resolve(self, query):
        query = query.lower().strip()
        if query in self.alias_db:

            return {
                "found": True,
                "cve": self.alias_db[query]["cve"],
                "confidence": self.alias_db[query]["confidence"]
            }

        return {"found": False}