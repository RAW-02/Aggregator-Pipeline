import time
import requests


class RetryManager:

    @staticmethod
    def execute(function, retries=5):
        last_exception = None

        for attempt in range(retries):
            try:
                return function()

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError
            ) as error:
                last_exception = error
                wait = 2 ** attempt

                print(
                    f"Retry {attempt + 1}/{retries} "
                    f"waiting {wait}s"
                )

                time.sleep(wait)

        raise last_exception