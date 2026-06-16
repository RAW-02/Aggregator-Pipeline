import json
from storage.opensearch_repository import OpenSearchRepository


class ReportGenerator:
    def generate(self):
        repo = OpenSearchRepository()
        
        records = repo.get_all()
        total = len(records)
        nvd = 0
        epss = 0
        github = 0
        kev = 0
        exploitdb = 0

        for record in records:
            if record.get("nvd_processed"):
                nvd += 1

            if record.get("epss_processed"):
                epss += 1

            if record.get("github_processed"):
                github += 1

            if record.get("kev_processed"):
                kev += 1

            if record.get("exploitdb_processed"):
                exploitdb += 1

        report = {
            "total": total,
            "nvd_completed": nvd,
            "epss_completed": epss,
            "kev_completed": kev,
            "exploitdb_completed": exploitdb,
            "github_completed": github
        }

        with open("reports/loading_report.json", "w") as f:
            json.dump(report, f, indent=4)

        return report