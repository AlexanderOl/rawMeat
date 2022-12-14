import glob
import os
import re
import shutil
import uuid
import requests_raw

from Managers.BodyChecker import BodyChecker
from Managers.CookieChecker import CookieChecker
from Managers.ParamChecker import ParamChecker
from Managers.RouteChecker import RouteChecker
from Models.MainInput import MainInput


class RawManager:
    def __init__(self):
        self._raw_dir = os.environ.get('raw_request_dir')
        self._ngok_url = os.environ.get('ngok_url')
        self._output_dir = os.environ.get('output_dir')

    def run(self):
        if not os.path.exists(self._raw_dir):
            os.makedirs(self._raw_dir)

        files = glob.glob(f'{self._raw_dir}/*.txt')
        if len(files) == 0:
            print(f'No files found {self._raw_dir}')
        else:
            print(f'{len(files)} files will be processed')
            for file in files:
                self.__process_file_request(file)

    def __process_file_request(self, file_request):
        main_input = self.__get_main_input(file_request)
        if main_input:
            route_checker = RouteChecker(main_input)
            route_checker.run()
            param_checker = ParamChecker(main_input)
            param_checker.run()
            body_checker = BodyChecker(main_input)
            body_checker.run()

            cookie_checker = CookieChecker(main_input)
            if re.search(r"c\w*\.txt", file_request):
                cookie_checker.run()

            if not route_checker.is_found and not body_checker.is_found and not cookie_checker.is_found:
                os.remove(f'{self._output_dir}/{main_input.output_filename}')

        os.remove(file_request)
        print(f'{file_request} file processed')

    def __get_main_input(self, file_request) -> MainInput:
        if 'application/xml' in file_request or 'text/xml' in file_request:
            print("Possible XXE found ('application/xml')")
        output_filename = f'{str(uuid.uuid4())[:8]}.txt'

        if not os.path.exists(self._output_dir):
            os.mkdir(self._output_dir)

        shutil.copyfile(file_request, f'{self._output_dir}/{output_filename}')
        text_file = open(file_request, "r")
        request = f'{text_file.read()}\r\n'
        host = request.split('\nHost: ')[1].split('\n')[0]
        if 'HTTP/1.1' in request:
            target_url = f'https://{host}/'
            first_request = request.encode()
        else:
            target_url = f'https://{host}/'
            first_request = request.replace('HTTP/2', 'HTTP/1.1').encode()
        text_file.close()

        try:
            first_response = requests_raw.raw(url=target_url, data=first_request, allow_redirects=False, timeout=5)
            return MainInput(target_url, first_request, first_response, output_filename, self._ngok_url)

        except Exception as inst:
            print(f'Url ({target_url}) - Exception: {inst}')
            os.remove(f'{self._output_dir}/{output_filename}')
