from pathlib import Path
import os

# ============================================
# Base
# ============================================

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================
# Database
# ============================================

DATABASE_DIR = BASE_DIR / "database"

VULNERABILITY_DIR = DATABASE_DIR / "vulnerabilities"

INDEX_DIR = DATABASE_DIR / "index"

CHECKPOINT_FILE = DATABASE_DIR / "checkpoint.json"

FAILED_QUEUE_FILE = DATABASE_DIR / "failed_cves.json"

# ============================================
# Logs
# ============================================

LOG_DIR = BASE_DIR / "logs"

# ============================================
# Loader
# ============================================

BATCH_SIZE = int(os.getenv("BATCH_SIZE", 500))

MAX_WORKERS = int(os.getenv("MAX_WORKERS", 10))

INITIAL_LOAD_LIMIT = os.getenv("INITIAL_LOAD_LIMIT")

if INITIAL_LOAD_LIMIT in (None, "", "0"):
    INITIAL_LOAD_LIMIT = None
else:
    INITIAL_LOAD_LIMIT = int(INITIAL_LOAD_LIMIT)

# ============================================
# API Sleep
# ============================================

NVD_DELAY = 1

EPSS_DELAY = 0.5

KEV_DELAY = 0.2

EXPLOITDB_DELAY = 0.5

GITHUB_DELAY = 3

ENRICHMENT_LIMIT = int(os.getenv("ENRICHMENT_LIMIT", 100))
ENRICHMENT_INTERVAL = int(os.getenv("ENRICHMENT_INTERVAL", 300))