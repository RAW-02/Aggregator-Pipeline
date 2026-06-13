import logging
import os

os.makedirs("logs", exist_ok=True)

class LoaderLogger:

    @staticmethod
    def get():
        logger = logging.getLogger("loader")

        if logger.handlers:
            return logger

        logger.setLevel(logging.INFO)

        handler = logging.FileHandler("logs/loader.log")

        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

        handler.setFormatter(formatter)

        logger.addHandler(handler)

        return logger