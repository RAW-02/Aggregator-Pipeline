class RankingResolver:
    @staticmethod
    def rank(results):
        unique = {}

        for item in results:
            if item.cve_id not in unique:
                unique[item.cve_id] = item

            elif item.score > unique[item.cve_id].score:
                unique[item.cve_id] = item

        ranked = list(unique.values())
        ranked.sort(
            key=lambda x: (x.score, x.published),
            reverse=True
        )

        return ranked