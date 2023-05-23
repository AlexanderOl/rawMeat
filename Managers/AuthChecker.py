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

    def find_auth_cookie_param(self, main_input, cookies_check_set=set):
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
