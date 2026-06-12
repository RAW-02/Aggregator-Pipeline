from storage.elasticsearch_client import ElasticsearchClient


class SearchService:

    def __init__(self):
        self.es = ElasticsearchClient().get_client()
        self.index_name = "vulnerabilities"

    def _execute_search(
        self,
        query,
        page=1,
        size=20
    ):
        

        from_ = (page - 1) * size

        return self.es.search(
            index=self.index_name,
            body=query,
            from_=from_,
            size=size
        )

    # ============================================
    # COMMON SORT HELPER
    # ============================================

    def apply_sort(self, query, sort):

        if not sort:
            return query

        sort_map = {
            "cvss": "cvss_score",
            "epss": "epss_score",
            "threat": "threat_score",
            "published": "published_date",
            "modified": "last_modified"
        }

        field = sort_map.get(sort.lower())

        if field:

            query["sort"] = [
                {
                    field: {
                        "order": "desc"
                    }
                }
            ]

        return query


    # =====================================================
    # FULL TEXT SEARCH
    # =====================================================

    def full_text_search(
        self,
        query_text,
        page=1,
        size=20,
        sort=None
    ):


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

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )
       

    # =====================================================
    # CVE SEARCH
    # =====================================================

    def search_by_cve(self, cve_id,page=1,size=20, sort=None):

        query = {
            "query": {
                "term": {
                    "cve_id": cve_id.upper()
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )



    # =====================================================
    # PRODUCT SEARCH
    # =====================================================

    def search_by_product(self, product,page=1,size=20, sort=None):

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

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # CWE SEARCH
    # =====================================================

    def search_by_cwe(self, cwe,page=1,size=20, sort=None):

        query = {
            "query": {
                "match": {
                    "cwe": cwe
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # SEVERITY SEARCH
    # =====================================================

    def search_by_severity(
        self,
        severity,
        page=1,
        size=20,
        sort=None
    ):

        query = {
            "query": {
                "term": {
                    "severity": severity.upper()
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )
    

    # =====================================================
    # KEV SEARCH
    # =====================================================

    def search_kev(self,page=1,size=20, sort=None):

        query = {
            "query": {
                "term": {
                    "kev_status": True
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # EXPLOIT AVAILABLE
    # =====================================================

    def search_exploitable(self,page=1,size=20, sort=None):

        query = {
            "query": {
                "term": {
                    "exploit_available": True
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # HIGH EPSS
    # =====================================================

    def search_high_epss(self, minimum_score=0.7,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "epss_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # HIGH CVSS
    # =====================================================

    def search_high_cvss(self, minimum_score=7.0,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "cvss_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # HIGH THREAT SCORE
    # =====================================================

    def search_high_threat(self, minimum_score=80,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "threat_score": {
                        "gte": minimum_score
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # GITHUB POCS AVAILABLE
    # =====================================================

    def search_with_pocs(self,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "github_repository_count": {
                        "gt": 0
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # PUBLISHED AFTER DATE
    # =====================================================

    def search_published_after(self, date,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "published_date": {
                        "gte": date
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # RECENTLY MODIFIED
    # =====================================================

    def search_modified_after(self, date,page=1,size=20, sort=None):

        query = {
            "query": {
                "range": {
                    "last_modified": {
                        "gte": date
                    }
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # SORT BY THREAT SCORE
    # =====================================================

    def top_threats(self, page=1,size=20, sort=None):

        query = {
            
            "sort": [
                {
                    "threat_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # SORT BY EPSS
    # =====================================================

    def top_epss(self, page=1,size=20, sort=None):

        query = {
            
            "sort": [
                {
                    "epss_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )

    # =====================================================
    # SORT BY CVSS
    # =====================================================

    def top_cvss(self, page=1,size=20, sort=None):

        query = {
            
            "sort": [
                {
                    "cvss_score": {
                        "order": "desc"
                    }
                }
            ]
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )
    


    def search_with_filters(
        self,
        filters,
        page=1,
        size=20,
        sort=None
    ):

        must_conditions = []

        if "severity" in filters:
            must_conditions.append(
                {
                    "term": {
                        "severity": filters["severity"]
                    }
                }
            )

        if "kev" in filters:
            must_conditions.append(
                {
                    "term": {
                        "kev_status": True
                    }
                }
            )

        if "exploit" in filters:
            must_conditions.append(
                {
                    "term": {
                        "exploit_available": True
                    }
                }
            )

        if "cwe" in filters:
            must_conditions.append(
                {
                    "match": {
                        "cwe": filters["cwe"]
                    }
                }
            )

        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            }
        }

        query = self.apply_sort(
            query,
            sort
        )

        return self._execute_search(
            query,
            page,
            size
        )
    

    