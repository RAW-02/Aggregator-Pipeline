from opensearchpy import OpenSearch
from dotenv import load_dotenv
import os

load_dotenv()

class OpenSearchClient:

    def __init__(self):
        self.client = OpenSearch(
            os.getenv("ELASTIC_HOST"),
            basic_auth=(
                os.getenv("ELASTIC_USERNAME"),
                os.getenv("ELASTIC_PASSWORD")
            ),
            http_compress=True,
            use_ssl=False,
            verify_certs=False
        )

    def get_client(self):
        return self.client