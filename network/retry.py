import time
import requests


class RetryManager:

    @staticmethod
    def execute(function):

        for attempt in range(5):

            try:

                return function()

            except requests.HTTPError as error:

                response = error.response

                if response is not None and response.status_code == 429:

                    wait = 2 ** attempt

                    print(
                        f"429 received. Sleeping {wait} seconds..."
                    )

                    time.sleep(wait)

                    continue

                raise

        return None