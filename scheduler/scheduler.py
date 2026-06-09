import time
import schedule
from scheduler.jobs import mitre_sync

schedule.every().day.at("02:00").do(mitre_sync)

print("Scheduler Started...")

while True:
    schedule.run_pending()
    time.sleep(30)