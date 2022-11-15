import glob
import os
import requests_raw
import shutil
import time
import uuid
from datetime import datetime
from MainInput import MainInput
from Managers.BodyChecker import BodyChecker
from Managers.RouteChecker import RouteChecker

InputDir = '/root/Desktop/share/RawRequests'
OutputDir = 'Output'
SleepDelay = 20


def get_main_input(file_request) -> MainInput:
    output_filename = f'{uuid.uuid4().hex}.txt'
    shutil.copyfile(file_request, f'{OutputDir}/{output_filename}')
    text_file = open(file_request, "r")
    request = f'{text_file.read()}\r\n'
    host = request.split('\nHost: ')[1].split('\n')[0]
    target_url = f'https://{host}/'
    first_request = request\
        .replace('HTTP/2', 'HTTP/1.1')
    text_file.close()

    first_response = requests_raw.raw(url=target_url, data=first_request, allow_redirects=False)
    if first_response.status_code < 400:
        return MainInput(target_url, first_request, first_response, output_filename)
    else:
        print(f"First request status:{first_response.status_code}. File will be removed")


def process_file_request(file_request):
    main_input = get_main_input(file_request)
    if main_input:
        route_checker = RouteChecker(main_input)
        route_checker.run()
        body_checker = BodyChecker(main_input)
        body_checker.run()

    os.remove(file_request)
    print(f'{file_request} file processed')


def start():
    if not os.path.exists(InputDir):
        os.makedirs(InputDir)
    print(f'[{datetime.now().strftime("%H:%M:%S")}]: Searching for incoming requests...')
    while True:

        files = glob.glob(f'{InputDir}/*.txt')
        if len(files) == 0:
            print('No files found.')
        else:
            print(f'{len(files)} files will be processed')
            for file in files:
                process_file_request(file)

        print(f'[{datetime.now().strftime("%H:%M:%S")}]: Searching complete. Sleep for {SleepDelay}')
        time.sleep(SleepDelay)


if __name__ == '__main__':
    start()

