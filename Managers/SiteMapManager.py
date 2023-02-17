import base64
import glob
import os
import pickle
import urllib
import uuid
from urllib.parse import urlparse

import requests_raw
import xml.etree.ElementTree as ET
from typing import List
from Managers.BodyChecker import BodyChecker
from Managers.HeaderChecker import HeaderChecker
from Managers.ParamChecker import ParamChecker
from Managers.RouteChecker import RouteChecker
from Managers.ThreadManager import ThreadManager
from Models.MainInput import MainInput


class SiteMapManager:
    def __init__(self):
        self._sitemap_dir = os.environ.get('sitemap_dir')
        self._ngok_url = os.environ.get('ngok_url')
        self._output_dir = os.environ.get('output_dir')
        self._out_of_scope_keys = os.environ.get('out_of_scope_keys').split(';')
        self._request_verbs_blacklist = ['OPTIONS', 'HEAD']
        self._target_urls_filepath = 'Targets/urls.txt'
        self._history_filepath = 'Output/history.txt'
        self._inputs_to_go_filepath = 'Output/inputs_to_go.txt'
        self._target_domain_urls = set()
        self._already_added_urls = {}
        self._chunk_size = 10

    def run(self):
        if not os.path.exists(self._sitemap_dir):
            os.makedirs(self._sitemap_dir)

        files = glob.glob(f'{self._sitemap_dir}/*')
        if len(files) == 0:
            print(f'No files found in {self._sitemap_dir}.')
        else:
            print(f'SiteMapManager will process {len(files)} files')

            for file in files:
                self.__process_sitemap(file)

    def __process_sitemap(self, file_request):
        self.__read_history()

        main_inputs = self.__read_inputs_to_go()
        if not main_inputs:
            main_inputs = self.__get_main_inputs(file_request)
            self.__write_inputs_to_go(main_inputs)

        thread_man = ThreadManager()
        thread_man.run_all(self.__run_batch, main_inputs)

        os.remove(file_request)
        os.remove(self._inputs_to_go_filepath)

        self.__write_history()
        print(f'{file_request} file processed')

    def __get_main_inputs(self, file_request) -> List[MainInput]:

        result: List[MainInput] = []

        if not os.path.exists(self._output_dir):
            os.mkdir(self._output_dir)

        self.__get_target_domain_urls()

        tree = ET.parse(file_request)
        root = tree.getroot()
        for item in root.findall('item'):

            target_url, first_request = self.__prepare_first_request(item)

            if not target_url or not first_request:
                continue

            host = item.find('host').text
            output_filename = f'{host}_{str(uuid.uuid4())[:8]}.txt'

            try:
                first_response = requests_raw.raw(url=target_url, data=first_request, allow_redirects=False, timeout=5)
                result.append(MainInput(target_url, first_request, first_response, output_filename, self._ngok_url))
            except Exception as inst:
                print(f'Exception ({inst}) on url: {target_url}')
                continue

        print(f'Found {len(result)} requests')

        return result

    def __divide_chunks(self, items):
        items_to_split = list(items)
        for i in range(0, len(items_to_split), self._chunk_size):
            yield items_to_split[i:i + self._chunk_size]

    def __check_if_added(self, base_url, path, http_verb: str):
        is_already_added = False
        parsed = urllib.parse.urlparse(path)
        params_to_check = filter(None, parsed.query.split("&"))
        key_to_check = ''
        for param_to_check in params_to_check:
            param_value_split = param_to_check.split('=')
            key_to_check += f'{param_value_split[0]};'

        if path[0] == '/':
            path = path[1:]

        target_url = f'{http_verb}-{base_url}{path}'
        added_path = self._already_added_urls.get(target_url)
        if added_path:
            if key_to_check in added_path:
                is_already_added = True
            else:
                self._already_added_urls[target_url].add(key_to_check)
        else:
            self._already_added_urls[target_url] = set([key_to_check])

        return is_already_added

    def __get_target_domain_urls(self):
        filepath = self._target_urls_filepath
        text_file = open(filepath, "r")
        urls = text_file.readlines()
        result = set()
        for url in urls:
            parsed_parts = urlparse(url)
            result.add(parsed_parts.netloc)

        self._target_domain_urls = result

    def __read_history(self):
        if os.path.exists(self._history_filepath) and os.path.getsize(self._history_filepath) > 0:
            file = open(self._history_filepath, 'rb')
            data = pickle.load(file)
            file.close()
            self._already_added_urls = data

    def __read_inputs_to_go(self):
        if os.path.exists(self._inputs_to_go_filepath) and os.path.getsize(self._inputs_to_go_filepath) > 0:
            file = open(self._inputs_to_go_filepath, 'rb')
            data = pickle.load(file)
            file.close()
            return data

    def __write_history(self):
        json_file = open(self._history_filepath, 'wb')
        pickle.dump(self._already_added_urls, json_file)
        json_file.close()

    def __write_inputs_to_go(self, main_inputs):
        json_file = open(self._inputs_to_go_filepath, 'wb')
        pickle.dump(main_inputs, json_file)
        json_file.close()

    def __prepare_first_request(self, item):
        host = item.find('host').text
        if not any(host in url for url in self._target_domain_urls):
            return None, None

        if any(key in host for key in self._out_of_scope_keys):
            return None, None

        protocol = item.find('protocol').text
        port = int(item.find('port').text)
        port_part = ''

        if port not in [80, 443]:
            port_part = f':{port}'

        try:
            target_url = f'{protocol}://{host}{port_part}/'
            first_request = base64.b64decode(item.find('request').text)
            path = item.find('path').text

            http_verb = str(first_request.decode()).split(' ', 1)[0]

            is_added = self.__check_if_added(target_url, path, http_verb)
            if is_added:
                return None, None

            if http_verb in self._request_verbs_blacklist:
                return None, None
        except Exception as inst:
            print(f'Unable to perform first request on {target_url}; Exception: {inst}')
            return None, None
        return target_url, first_request

    def __run_batch(self, main_input):
        route_checker = RouteChecker(main_input)
        route_checker.run()
        param_checker = ParamChecker(main_input)
        param_checker.run()
        body_checker = BodyChecker(main_input)
        body_checker.run()
        header_checker = HeaderChecker(main_input)
        header_checker.run()

