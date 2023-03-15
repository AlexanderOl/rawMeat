import re
from http.cookies import SimpleCookie

import requests_raw
from typing import List
from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class AuthChecker:
    def __init__(self):
        self._outputAuthDir = 'Output/Auth'
        self._avoid_status_code = 429
        self._victim_list = {}
        self._attacker_url_cookies = {}

    def run(self, file_request, main_inputs: List[MainInput]):
        if re.search(r"a1\w*", file_request):
            self.__add_victim(main_inputs)
        elif re.search(r"a2\w*", file_request):
            self.__add_attacker(main_inputs)

    def __add_victim(self, main_inputs: List[MainInput]):
        self._victim_list = {}
        for main_input in main_inputs:

            if main_input.first_resp.status_code != 200 or 'Cookie: ' not in main_input.first_req:
                continue

            if main_input.target_url in self._victim_list:
                self._victim_list[main_input.target_url].append(main_input)
            else:
                self._victim_list[main_input.target_url] = [main_input]

        if self._attacker_url_cookies:
            self.__run_attack()

    def __add_attacker(self, main_inputs: List[MainInput]):
        self._attacker_url_cookies = {}
        for main_input in main_inputs:

            if main_input.first_resp.status_code != 200 or 'Cookie: ' not in main_input.first_req:
                continue
            cookie_split = main_input.first_req.split('Cookie: ')
            attacker_cookies = cookie_split[1].split('\n')[0]

            if main_input.target_url not in self._attacker_url_cookies:
                self._attacker_url_cookies[main_input.target_url] = attacker_cookies

        if self._victim_list:
            self.__run_attack()

    def __run_attack(self):
        for target_url in self._attacker_url_cookies:
            victim_main_inputs = self._victim_list[target_url]
            if not victim_main_inputs:
                continue
            status_code, auth_cookie_param, raw_cookies = self.__find_auth_cookie_param(victim_main_inputs[0])
            if not auth_cookie_param:
                print(f'({target_url}) Cookies do not affect the user authentication')
                continue
            for curr_input in victim_main_inputs:
                self.__check_idor(curr_input, self._attacker_url_cookies[target_url])

    def __check_idor(self, curr_input: MainInput, attacker_cookie):
        cookie_split = curr_input.first_req.split('Cookie: ')
        raw_cookies = cookie_split[1].split('\n', 1)
        new_request = f'{cookie_split[0]}Cookie: {attacker_cookie}\n{raw_cookies[1]}'.encode()

        new_response = requests_raw.raw(url=curr_input.target_url, data=new_request, allow_redirects=False,
                                        verify=False,
                                        timeout=5)
        if new_response.status_code == curr_input.first_resp.status_code:
            splitted = curr_input.first_req.split(' ', 2)
            log_header_msg = f'Auth IDOR Method: {splitted[0]}; ' \
                             f'URL: {curr_input.target_url}{splitted[1]}; ' \
                             f'FFILE: {curr_input.output_filename}'
            print(log_header_msg)
            bc = BaseChecker(curr_input)
            bc.save_found(log_header_msg, [new_request, curr_input.first_req], self._outputAuthDir)

    def __find_auth_cookie_param(self, main_input):
        cookie_split = main_input.first_req.split('Cookie: ')
        if len(cookie_split) == 2:
            raw_cookies = cookie_split[1].split('\n')[0]
            cookie = SimpleCookie()
            cookie.load(raw_cookies)
            cookies = {}
            for key, morsel in cookie.items():
                cookies[key] = morsel.value

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
                    return response.status_code, cookie_param, raw_cookies

            return None, None, None

    # def __check_group(self, group: List[MainInput]):
    #     auth_cookie_param = ''
    #     auth_error_status_code = 0
    #     auth_main_input = {}
    #
    #     request_count_with_diff_cookies = {}
    #
    #     for curr_input in group:
    #
    #         if not auth_cookie_param:
    #             auth_error_status_code, auth_cookie_param, raw_cookies = self.__find_auth_cookie_param(curr_input)
    #             auth_main_input = curr_input
    #             break
    #
    #     if not auth_cookie_param:
    #         return
    #
    #     for curr_input in group:
    #         if curr_input == auth_main_input:
    #             continue
    #         else:
    #             self.__check_auth_input(auth_error_status_code, auth_cookie_param, curr_input)

    # def __check_auth_input(self, auth_status_code, auth_cookie_param, curr_input):
    #     raw_request = f'{curr_input.first_req.replace(auth_cookie_param, "")}'.encode()
    #     response = requests_raw.raw(url=curr_input.target_url,
    #                                 data=raw_request,
    #                                 allow_redirects=False,
    #                                 timeout=5)
    #     if response.status_code != auth_status_code:
    #         log_header_msg = f'Auth cookie param: {auth_cookie_param} doesn\'t affect request' \
    #                          f'FILE: {curr_input.output_filename}'
    #         print(log_header_msg)
    #         bc = BaseChecker(curr_input)
    #         bc.save_found(log_header_msg, [raw_request], self._outputAuthDir)
