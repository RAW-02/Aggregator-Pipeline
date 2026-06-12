import json
import os


class CacheManager:

    def __init__(self):

        self.directory = "cache"

        os.makedirs(

            self.directory,

            exist_ok=True

        )

    def file(self, key):

        return os.path.join(

            self.directory,

            f"{key}.json"

        )

    def exists(self, key):

        return os.path.exists(

            self.file(key)

        )

    def get(self, key):

        with open(

            self.file(key),

            "r"

        ) as f:

            return json.load(f)

    def put(self, key, value):

        with open(

            self.file(key),

            "w"

        ) as f:

            json.dump(

                value,

                f,

                indent=4

            )