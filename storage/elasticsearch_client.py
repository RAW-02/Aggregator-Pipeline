from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os

load_dotenv()

class ElasticsearchClient:

    def __init__(self):

        self.client = Elasticsearch(
            os.getenv("ELASTIC_HOST"),
            basic_auth=(
                os.getenv("ELASTIC_USERNAME"),
                os.getenv("ELASTIC_PASSWORD")
            ),
            verify_certs=False
        )

    def get_client(self):
        return self.client