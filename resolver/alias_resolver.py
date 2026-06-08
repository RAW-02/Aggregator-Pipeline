from github_engine.main import github_engine
from resolver.resolver_result import ResolverResult

class AliasResolver:

    def resolve(self, query):
        github = github_engine(query)
        results = []
        primary = github["primary_cve"]

        if primary:
            results.append(
                ResolverResult(
                    cve_id=primary,
                    score=95,
                    source="Github",
                    matched_by="alias",
                    published="",
                    last_modified=""
                )
            )

        return results