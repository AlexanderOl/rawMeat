import glob
import os
import re

import requests_raw
import shutil
import time
import uuid
from datetime import datetime

from Managers.CookieChecker import CookieChecker
from Models.MainInput import MainInput
from Managers.BodyChecker import BodyChecker
from Managers.RouteChecker import RouteChecker

InputDir = 'D:\share\RawRequests'
OutputDir = 'Output'
SleepDelay = 30


def get_main_input(file_request) -> MainInput:
    if 'application/xml' in file_request:
        print("Possible XXE found ('application/xml')")
    output_filename = f'{uuid.uuid4().hex}.txt'
    shutil.copyfile(file_request, f'{OutputDir}/{output_filename}')
    text_file = open(file_request, "r")
    request = f'{text_file.read()}\r\n'
    host = request.split('\nHost: ')[1].split('\n')[0]
    if 'HTTP/1.1' in request:
        target_url = f'http://{host}/'
        first_request = request.encode()
    else:
        target_url = f'https://{host}/'
        first_request = request.replace('HTTP/2', 'HTTP/1.1').encode()
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

        if re.search(r"c\w*\.txt", file_request):
            cookie_checker = CookieChecker(main_input)
            cookie_checker.run()

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

