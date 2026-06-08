from dataclasses import dataclass

@dataclass
class ResolvedCVE:
    cve_id: str
    published: str
    last_modified: str
    confidence: float = 1.0
    source: str = "NVD"
    query_type: str = ""

    @staticmethod
    def resolve(cve):
        return [
            ResolvedCVE(
                cve_id=cve,
                published="",
                last_modified="",
                source="USER",
                query_type="cve"
            )
        ]