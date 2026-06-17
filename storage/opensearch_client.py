from opensearchpy import OpenSearch
from dotenv import load_dotenv
import os

load_dotenv()

class OpenSearchClient:

    def __init__(self):
        self.client = OpenSearch(
            hosts=[
                {
                    "host": os.getenv("OPENSEARCH_HOST", "opensearch"),
                    "port": int(os.getenv("OPENSEARCH_PORT", 9200))
                }
            ],
            use_ssl=False,
            verify_certs=False,
            http_compress=True
        )

    def get_client(self):
        return self.client