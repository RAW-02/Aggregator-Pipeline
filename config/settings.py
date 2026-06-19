from pathlib import Path
import os

# Base
BASE_DIR = Path(__file__).resolve().parent.parent

# Database
DATABASE_DIR = BASE_DIR / "database"
VULNERABILITY_DIR = DATABASE_DIR / "vulnerabilities"
CHECKPOINT_FILE = DATABASE_DIR / "checkpoint.json"
FAILED_QUEUE_FILE = DATABASE_DIR / "failed_cves.json"

# Logs

LOG_DIR = BASE_DIR / "logs"
# Loader

BATCH_SIZE = int(os.getenv("BATCH_SIZE", 500))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 15))
INITIAL_LOAD_LIMIT = os.getenv("INITIAL_LOAD_LIMIT")

if INITIAL_LOAD_LIMIT in (None, "", "0"):
    INITIAL_LOAD_LIMIT = None
else:
    INITIAL_LOAD_LIMIT = int(INITIAL_LOAD_LIMIT)

# API Sleep
EPSS_DELAY = 0.5

KEV_DELAY = 0.2

EXPLOITDB_DELAY = 0.5

ENRICHMENT_LIMIT = int(os.getenv("ENRICHMENT_LIMIT", 200))
ENRICHMENT_INTERVAL = int(os.getenv("ENRICHMENT_INTERVAL", 90))

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_TIMEOUT = int(os.getenv("NVD_TIMEOUT", 60))
NVD_MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", 5))
NVD_DELAY = float(os.getenv("NVD_DELAY", 1))

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_TIMEOUT = int(os.getenv("GITHUB_TIMEOUT", 30))
GITHUB_MAX_RETRIES = int(os.getenv("GITHUB_MAX_RETRIES", 5))
GITHUB_DELAY = float(os.getenv("GITHUB_DELAY", 2))