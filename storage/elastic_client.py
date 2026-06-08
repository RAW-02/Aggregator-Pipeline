from elasticsearch import Elasticsearch

class ElasticClient:
    _client = None

    @classmethod
    def get_client(cls):
        if cls._client is None:
            cls._client = Elasticsearch(
                "http://localhost:9200"
            )

            if not cls._client.ping():
                raise ConnectionError(
                    "Elasticsearch is not running!"
                )

        return cls._client