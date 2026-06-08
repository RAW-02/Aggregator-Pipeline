INDEX_NAME = "vulnerabilities"

INDEX_MAPPING = {

    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },

    "mappings": {
        "properties": {

            "cve_id": {
                "type": "keyword"
            },

            "description": {
                "type": "text"
            },

            "published_date": {
                "type": "date",
                "format": "strict_date_optional_time||yyyy-MM-dd"
            },

            "last_modified": {
                "type": "date",
                "format": "strict_date_optional_time||yyyy-MM-dd"
            },

            "cvss_score": {
                "type": "float"
            },

            "severity": {
                "type": "keyword"
            },

            "cwe": {
                "type": "keyword"
            },

            "products": {
                "type": "keyword"
            },

            "exploit_available": {
                "type": "boolean"
            },

            "exploit_count": {
                "type": "integer"
            },

            "kev_status": {
                "type": "boolean"
            },

            "epss_score": {
                "type": "float"
            },

            "github_repository_count": {
                "type": "integer"
            },

            "github_aliases": {
                "type": "keyword"
            },

            "threat_score": {
                "type": "float"
            }
        }
    }
}