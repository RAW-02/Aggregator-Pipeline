import logging
import os

from config.settings import LOG_DIR

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("pipeline")

logger.setLevel(logging.INFO)

formatter = logging.Formatter(

    "%(asctime)s | %(levelname)s | %(message)s"

)

file_handler = logging.FileHandler(

    os.path.join(LOG_DIR, "pipeline.log"),

    encoding="utf-8"

)

file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()

console_handler.setFormatter(formatter)

logger.addHandler(file_handler)

logger.addHandler(console_handler)