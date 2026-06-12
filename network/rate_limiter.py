import threading
import time


class RateLimiter:

    def __init__(self, requests_per_second):

        self.interval = 1.0 / requests_per_second

        self.lock = threading.Lock()

        self.last_request = 0

    def wait(self):

        with self.lock:

            current = time.time()

            elapsed = current - self.last_request

            if elapsed < self.interval:

                time.sleep(self.interval - elapsed)

            self.last_request = time.time()