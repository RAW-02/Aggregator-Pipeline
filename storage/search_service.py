from storage.elasticsearch_client import ElasticsearchClient


class SearchService:

    def __init__(self):
        self.es = ElasticsearchClient().get_client()
        self.index_name = "vulnerabilities"

    # =====================================================
    # FULL TEXT SEARCH
    # =====================================================

    def full_text_search(self, query_text):

        

        query = {
            "query": {
                "multi_match": {
                    "query": query_text,
                    "fields": [

                        "cve_id^15",

                        "description^10",

                        "products^8",

                        "product_keywords^12",

                        "severity^5",

                        "cwe^8",

                        "github_aliases^6",

                        "references"

                    ],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query,
            size=50
        )
        print(
            "FOUND =",
            result["hits"]["total"]["value"]
        )

    # =====================================================
    # CVE SEARCH
    # =====================================================

    def search_by_cve(self, cve_id):

        query = {
            "query": {
                "term": {
                    "cve_id": cve_id.upper()
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )



    # =====================================================
    # PRODUCT SEARCH
    # =====================================================

    def search_by_product(self, product):

        query = {
            "query": {
                "bool": {
                    "should": [

                        {
                            "match": {
                                "product_keywords": product
                            }
                        },

                        {
                            "wildcard": {
                                "products.keyword": {
                                    "value": f"*{product.lower()}*"
                                }
                            }
                        }

                    ]
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # CWE SEARCH
    # =====================================================

    def search_by_cwe(self, cwe):

        query = {
            "query": {
                "match": {
                    "cwe": cwe
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # SEVERITY SEARCH
    # =====================================================

    def search_by_severity(self, severity):

        query = {
            "query": {
                "term": {
                    "severity": severity.upper()
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )
    

    # =====================================================
    # KEV SEARCH
    # =====================================================

    def search_kev(self):

        query = {
            "query": {
                "term": {
                    "kev_status": True
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # EXPLOIT AVAILABLE
    # =====================================================

    def search_exploitable(self):

        query = {
            "query": {
                "term": {
                    "exploit_available": True
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # HIGH EPSS
    # =====================================================

    def search_high_epss(self, minimum_score=0.7):

        query = {
            "query": {
                "range": {
                    "epss_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # HIGH CVSS
    # =====================================================

    def search_high_cvss(self, minimum_score=7.0):

        query = {
            "query": {
                "range": {
                    "cvss_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # HIGH THREAT SCORE
    # =====================================================

    def search_high_threat(self, minimum_score=80):

        query = {
            "query": {
                "range": {
                    "threat_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # GITHUB POCS AVAILABLE
    # =====================================================

    def search_with_pocs(self):

        query = {
            "query": {
                "range": {
                    "github_repository_count": {
                        "gt": 0
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # PUBLISHED AFTER DATE
    # =====================================================

    def search_published_after(self, date):

        query = {
            "query": {
                "range": {
                    "published_date": {
                        "gte": date
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # RECENTLY MODIFIED
    # =====================================================

    def search_modified_after(self, date):

        query = {
            "query": {
                "range": {
                    "last_modified": {
                        "gte": date
                    }
                }
            }
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # SORT BY THREAT SCORE
    # =====================================================

    def top_threats(self, size=20):

        query = {
            "size": size,
            "sort": [
                {
                    "threat_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # SORT BY EPSS
    # =====================================================

    def top_epss(self, size=20):

        query = {
            "size": size,
            "sort": [
                {
                    "epss_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )

    # =====================================================
    # SORT BY CVSS
    # =====================================================

    def top_cvss(self, size=20):

        query = {
            "size": size,
            "sort": [
                {
                    "cvss_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        return self.es.search(
            index=self.index_name,
            body=query
        )
    

    