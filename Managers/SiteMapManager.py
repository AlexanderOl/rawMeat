import base64
import glob
import os
import re
import shutil
import urllib
import uuid
import xml.etree.ElementTree as ET
from typing import List

import requests_raw

from Managers.BodyChecker import BodyChecker
from Managers.CookieChecker import CookieChecker
from Managers.ParamChecker import ParamChecker
from Managers.RouteChecker import RouteChecker
from Models.MainInput import MainInput


class SiteMapManager:
    def __init__(self):
        self._sitemap_dir = os.environ.get('sitemap_dir')
        self._ngok_url = os.environ.get('ngok_url')
        self._output_dir = os.environ.get('output_dir')
        self._already_added_pathes = {}

    def run(self):
        if not os.path.exists(self._sitemap_dir):
            os.makedirs(self._sitemap_dir)

        files = glob.glob(f'{self._sitemap_dir}/*')
        if len(files) == 0:
            print(f'No files found in {self._sitemap_dir}.')
        else:
            print(f'SiteMapManager will be process {len(files)} files')
            for file in files:
                self.__process_sitemap(file)

    def __process_sitemap(self, file_request):

        main_inputs = self.__get_main_inputs(file_request)
        if len(main_inputs) > 0:
            for main_input in main_inputs:
                route_checker = RouteChecker(main_input)
                route_checker.run()
                param_checker = ParamChecker(main_input)
                param_checker.run()
                body_checker = BodyChecker(main_input)
                body_checker.run()

                cookie_checker = CookieChecker(main_input)
                if re.search(r"c\w*\.txt", file_request):
                    cookie_checker.run()

                if not route_checker.is_found and not body_checker.is_found and not cookie_checker.is_found and not param_checker.is_found:
                    os.remove(f'{self._output_dir}/{main_input.output_filename}')

        os.remove(file_request)
        print(f'{file_request} file processed')

    def __get_main_inputs(self, file_request) -> List[MainInput]:

        result: List[MainInput] = []

        if not os.path.exists(self._output_dir):
            os.mkdir(self._output_dir)

        tree = ET.parse(file_request)
        root = tree.getroot()
        for item in root.findall('item'):

            is_added = self.__check_if_added(item)
            if is_added:
                continue

            output_filename = f'{str(uuid.uuid4())[:8]}.txt'
            shutil.copyfile(file_request, f'{self._output_dir}/{output_filename}')
            host = item.find('host').text
            protocol = item.find('protocol').text
            port = int(item.find('port').text)
            port_part = ''

            if port not in [80, 443]:
                port_part = f':{port}'

            target_url = f'{protocol}://{host}{port_part}/'
            first_request = base64.b64decode(item.find('request').text)
            if 'application/xml' in file_request or 'text/xml' in file_request:
                print("Possible XXE found ('application/xml')")
            first_response = requests_raw.raw(url=target_url, data=first_request, allow_redirects=False, timeout=5)

            result.append(MainInput(target_url, first_request, first_response, output_filename, self._ngok_url))

        print(f'Found {len(result)} requests')

        return result

    def __check_if_added(self, item):
        is_already_added = False
        path = item.find('path').text
        parsed = urllib.parse.urlparse(path)
        params_to_check = filter(None, parsed.query.split("&"))
        key_to_check = ''
        for param_to_check in params_to_check:
            param_value_split = param_to_check.split('=')
            key_to_check += f'{param_value_split[0]};'

        added_path = self._already_added_pathes.get(parsed.path)
        if added_path:
            if key_to_check in added_path:
                is_already_added = True
            else:
                self._already_added_pathes[parsed.path].append(key_to_check)
        else:
            self._already_added_pathes[parsed.path] = [key_to_check]

        return is_already_added
