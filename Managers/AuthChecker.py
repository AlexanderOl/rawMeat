import os
import re
from datetime import datetime
from http.cookies import SimpleCookie

import requests_raw
from typing import List
from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class AuthChecker:
    def __init__(self):
        self._outputAuthDir = 'Output/Auth'
        self._avoid_status_code = 429
        self._victim_list: dict[str, List[MainInput]] = {}
        self._attacker_url_cookies: dict[str, str] = {}
        self._attacker_auth_header_values: dict[str, str] = {}
        self._auth_header_key = 'Authorization: '
        self._cookie_header_key = 'Cookie: '

    def run(self, file_request, main_inputs: List[MainInput]):
        filename = os.path.basename(file_request)
        if filename == 'a1':
            self.__add_victim(main_inputs)
        elif filename == 'a2':
            self.__add_attacker(main_inputs)


    def __add_victim(self, main_inputs: List[MainInput]):
        self._victim_list = {}
        for main_input in main_inputs:

            if main_input.first_resp.status_code != 200 or \
                (self._cookie_header_key not in main_input.first_req
                 and self._auth_header_key not in main_input.first_req):
                continue

            if main_input.target_url in self._victim_list:
                self._victim_list[main_input.target_url].append(main_input)
            else:
                self._victim_list[main_input.target_url] = [main_input]

        print(f'[{datetime.now().strftime("%H:%M:%S")}]: Victim added')

        if self._attacker_url_cookies:
            self.__run_attack()

    def __add_attacker(self, main_inputs: List[MainInput]):

        for main_input in main_inputs:

            if main_input.first_resp.status_code != 200:
                continue
            if self._cookie_header_key in main_input.first_req:
                cookie_split = main_input.first_req.split(self._cookie_header_key)
                attacker_cookies = cookie_split[1].split('\n')[0]

                if main_input.target_url not in self._attacker_url_cookies:
                    self._attacker_url_cookies[main_input.target_url] = attacker_cookies

            if self._auth_header_key in main_input.first_req:
                auth_token = main_input.first_req.split(self._auth_header_key)[1].split('\n', 1)[0]
                self._attacker_auth_header_values[main_input.target_url] = auth_token

        print(f'[{datetime.now().strftime("%H:%M:%S")}]: Atacker added')

        if self._victim_list:
            self.__run_attack()

    def __run_attack(self):

        for target_url in self._attacker_auth_header_values:

            if target_url not in self._victim_list:
                continue

            self.__auth_header_idor_check(target_url)

        for target_url in self._attacker_url_cookies:

            if target_url not in self._victim_list:
                continue

            self.__cookie_idor_check(target_url)

    def __check_idor(self, curr_input: MainInput, attacker_cookie):
        cookie_split = curr_input.first_req.split(self._cookie_header_key)
        raw_cookies = cookie_split[1].split('\n', 1)
        new_request = f'{cookie_split[0]}{self._cookie_header_key}{attacker_cookie}\n{raw_cookies[1]}'.encode()
        try:
            new_response = requests_raw.raw(url=curr_input.target_url, data=new_request, allow_redirects=False,
                                            verify=False,
                                            timeout=5)
        except Exception as inst:
            print(f'__check_idor Exception: {inst}')
            return

        if new_response.status_code == curr_input.first_resp.status_code:
            splitted = curr_input.first_req.split(' ', 2)
            log_header_msg = f'Cookie IDOR Method: {splitted[0]}; ' \
                             f'URL: {curr_input.target_url}{splitted[1]}; ' \
                             f'FILE: {curr_input.output_filename}'
            print(log_header_msg)
            bc = BaseChecker(curr_input)
            bc.save_found(log_header_msg, [new_request, curr_input.first_req], self._outputAuthDir)



    def find_auth_cookie_param(self, main_input, cookies_check_set):
        cookie_split = main_input.first_req.split(self._cookie_header_key)
        if len(cookie_split) == 2:
            raw_cookies = str(cookie_split[1].split('\n')[0]).strip()

            cookies = {}
            cookies_k_v = raw_cookies.split('; ')
            cookies_set = set()
            for k_v in cookies_k_v:
                splitted = k_v.split('=')
                if len(splitted) == 2:
                    cookies[splitted[0]] = splitted[1]
                else:
                    cookies[splitted[0]] = ''
                cookies_check_set.add(splitted[0])

            if cookies_set == cookies_check_set:
                return None, raw_cookies

            cookie_requests = {}
            for item in cookies:
                original_str = f'{item}={cookies[item]}'
                cookie_requests[original_str] = main_input.first_req.replace(original_str, '')

            init_status_code = main_input.first_resp.status_code
            for cookie_param in cookie_requests:
                try:
                    raw_request = f'{cookie_requests[cookie_param]}'.encode()
                    response = requests_raw.raw(url=main_input.target_url,
                                                data=raw_request,
                                                verify=False,
                                                allow_redirects=False,
                                                timeout=5)
                except Exception as inst:
                    print(f'Exception ({inst}) on url: {main_input.target_url}')
                    continue

                if response.status_code != init_status_code and response.status_code != self._avoid_status_code:
                    print(f'({main_input.target_url}) Auth param found - {cookie_param}')
                    return cookie_param, cookies_set

            print(f'({main_input.target_url}) Cookies do not affect the user authentication')
            return None, cookies_set

    def __cookie_idor_check(self, target_url: str):
        victim_main_inputs = self._victim_list[target_url]
        auth_cookie_param = ''
        checked_cookies = ''
        for curr_input in victim_main_inputs:
            if not auth_cookie_param:
                auth_cookie_param, cookies_set = self.find_auth_cookie_param(curr_input, checked_cookies)
                if not auth_cookie_param:
                    checked_cookies = cookies_set
                    continue

            self.__check_idor(curr_input, self._attacker_url_cookies[target_url])

    def __auth_header_idor_check(self, target_url):
        victim_main_inputs = self._victim_list[target_url]
        for curr_input in victim_main_inputs:
            if self._auth_header_key in curr_input.first_req and target_url in self._attacker_auth_header_values:
                attacker_auth_token = self._attacker_auth_header_values[target_url]
                auth_split = curr_input.first_req.split(self._auth_header_key)
                other_part = auth_split[1].split('\n', 1)
                new_request = f'{auth_split[0]}{self._auth_header_key}{attacker_auth_token}\n{other_part[1]}'.encode()
                try:
                    new_response = requests_raw.raw(url=curr_input.target_url, data=new_request, allow_redirects=False,
                                                    verify=False,
                                                    timeout=5)
                except Exception as inst:
                    print(f'__check_idor Exception: {inst}')
                    return

                if new_response.status_code == curr_input.first_resp.status_code:
                    splitted = curr_input.first_req.split(' ', 2)
                    log_header_msg = f'Authorization Header IDOR Method: {splitted[0]}; ' \
                                     f'URL: {curr_input.target_url}{splitted[1]}; ' \
                                     f'FILE: {curr_input.output_filename}'
                    print(log_header_msg)
                    bc = BaseChecker(curr_input)
                    bc.save_found(log_header_msg, [new_request, curr_input.first_req], self._outputAuthDir)
