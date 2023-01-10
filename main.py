import time
from datetime import datetime
from dotenv import load_dotenv
from Managers.RawManager import RawManager
from Managers.SiteMapManager import SiteMapManager

SleepDelay = 30

if __name__ == '__main__':
    load_dotenv('config.env')

    print(f'[{datetime.now().strftime("%H:%M:%S")}]: Searching for incoming requests...')

    raw_man = RawManager()
    sitemap_man = SiteMapManager()

    while True:
        raw_man.run()
        sitemap_man.run()
        print(f'[{datetime.now().strftime("%H:%M:%S")}]: Searching complete. Sleep for {SleepDelay}')
        time.sleep(SleepDelay)
