from resolver.resolver_result import ResolverResult

class CVEResolver:

    @staticmethod
    def resolve(cve):
        return [
            ResolverResult(
                cve_id=cve,
                score=100,
                source="USER",
                matched_by="cve",
                published="",
                last_modified=""

            )
        ]