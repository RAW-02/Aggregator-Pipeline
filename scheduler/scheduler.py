import time
import schedule
from scheduler.jobs import (refresh_all_sources, enrichment_sync)

# Every 6 hours
schedule.every(6).hours.do(refresh_all_sources)

# Every Sunday
schedule.every().sunday.at("03:00").do(enrichment_sync)

print("Scheduler Started...")

while True:
    try:
        schedule.run_pending()
    except Exception as e:
        print(e)    
    time.sleep(30)