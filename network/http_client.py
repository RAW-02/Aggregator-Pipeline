import requests

class HttpClient:

    _session = None

    @classmethod
    def session(cls):

        if cls._session is None:

            cls._session = requests.Session()

            cls._session.headers.update(
                {
                    "User-Agent": "Threat-Intelligence-Platform/1.0"
                }
            )

        return cls._session