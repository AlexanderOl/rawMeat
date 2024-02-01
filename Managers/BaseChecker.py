import os
from typing import List

import requests_raw
from requests import RequestException
from urllib3.exceptions import ReadTimeoutError

from Models.Idor import Idor
from Models.MainInput import MainInput


class BaseChecker:
    def __init__(self, main_input: MainInput):
        self._bool_diff_rate = 0.1
        self._injection_payloads = ['%27', '\\', '<poc>', '""poc\'\'', '%22', '%5C', '\'',
                                    '{{888*888}}', '"%2bstr(888*888)%2b"']
        self._time_based_payloads = [
            {'True': '\'OR(if(1=1,sleep(5),0))OR\'', 'False': '\'OR(if(1=2,sleep(5),0))OR\''},
            {'True': '"OR(if(1=1,sleep(5),0))OR"', 'False': '"OR(if(1=2,sleep(5),0))OR"'},
            {'True': '1\'; WAITFOR DELAY \'00:00:05', 'False': '1\'; WAITFOR DELAY \'00:00:00'},
            {'True': '\' OR \'1\'>(SELECT \'1\' FROM PG_SLEEP(5)) OR \'',
             'False': '\' OR \'1\'>(SELECT \'1\' FROM PG_SLEEP(0)) OR \''}
        ]
        self._bool_based_payloads = [
            {'TruePld': '\'OR(1=1)OR\'', 'FalsePld': '\'OR(1=2)OR\'', 'True2Pld': '\'OR(2=2)OR\''},
            {'TruePld': '"OR(1=1)OR"', 'FalsePld': '"OR(1=2)OR"', 'True2Pld': '"OR(2=2)OR"'}
        ]
        self._false_positives = ['malformed request syntax',
                                 'use esm export syntax, instead:',
                                 'invalid parameter value for aura.format',
                                 'known to have no newer js syntax',
                                 'to enable the details of this specific',
                                 'the request cannot be fulfilled due to bad',
                                 'http 404. the resource you are looking for',
                                 'symantecinternalerror',
                                 'a potentially dangerous request',
                                 '<customErrors mode="Off"/>']

        self._injections_to_check = ['syntax', '<poc>', '""poc\'\'', 'xpath', 'internalerror', 'warning: ',
                                     'server error in', 'Use of undefined constant', '788544']
        self._xxe_to_check = ['root:', 'XXE found!', 'exception', '<foo>', 'Use of undefined constant']
        self._outputIdorDir = 'Output/Idor'
        self._outputSstiDir = 'Output/Ssti'
        self._outputSsrfDir = 'Output/Ssrf'
        self._outputInjectionsDir = 'Output/Injections'
        self._outputXxeDir = 'Output/Xxe'
        self._outputTimeBasedDir = 'Output/TimeBased'
        self._outputBoolBasedDir = 'Output/BoolBased'
        self._main_input = main_input
        self.is_found = False
        self._found_headers = set()
        self._delay_in_seconds = 5

    def check_injections(self, injection_payloads: []):

        for index, request in enumerate(injection_payloads):
            request = f'{request}'.encode()
            try:
                response = requests_raw.raw(url=self._main_input.target_url,
                                            data=request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=5)

                web_page = response.text.lower()
                self.injection_keyword_checks(web_page, response, request)
                if response.status_code == 500:
                    log_header_msg = f'{response.status_code} Status: - {web_page[0:100]}'
                    print(log_header_msg)
                    # self.save_found(log_header_msg, [request], self._outputInjectionsDir)
            except:
                break

    def check_idor(self, idor_payloads: List[Idor]):

        for idor_payload in idor_payloads:
            check_results = []
            idor_requests = idor_payload.requests
            for request in idor_requests:
                try:
                    response = requests_raw.raw(
                        url=self._main_input.target_url,
                        data=request.encode(),
                        verify=False,
                        allow_redirects=False,
                        timeout=5)
                    if response.status_code != self._main_input.first_resp.status_code:
                        check_results = []
                        break
                    check_results.append(response)
                except:
                    break

                if len(check_results) == len(idor_requests):
                    responses_length = [len(response.text) for response in check_results]
                    responses_length.append(len(self._main_input.first_resp.text))
                    if len(responses_length) == len(set(responses_length)):
                        log_header_msg = f'FOUND IDOR in param:{idor_payload.param}; ' \
                                         f'REQUEST: {request[0:100]}; ' \
                                         f'FILE: {self._main_input.output_filename}'
                        print(log_header_msg)
                        self.save_found(log_header_msg, idor_requests, self._outputIdorDir)

    def check_ssti(self, ssti_payloads: []):
        for ssti_requests in ssti_payloads:
            check_results = []
            for request in ssti_requests:
                try:
                    response = requests_raw.raw(url=self._main_input.target_url,
                                                data=request.encode(),
                                                verify=False,
                                                allow_redirects=False,
                                                timeout=5)
                    if response.status_code != self._main_input.first_resp.status_code:
                        check_results = []
                        break
                    check_results.append(response)
                except:
                    break

            if len(check_results) == len(ssti_requests):
                ssti_responses_length = [len(response.text) for response in check_results]
                main_responses_length = len(self._main_input.first_resp.text)
                if set(ssti_responses_length) == 1 and ssti_responses_length[0] != main_responses_length:
                    log_header_msg = f'FOUND SSTI: {ssti_requests[0][0:100]};' \
                                     f'FILE: {self._main_input.output_filename}'
                    print(log_header_msg)
                    self.save_found(log_header_msg, ssti_requests, self._outputSstiDir)

    def check_ssrf(self, ssrf_payloads: []):
        for request in ssrf_payloads:
            request = f'{request}'.encode()
            try:
                response = requests_raw.raw(url=self._main_input.target_url,
                                            data=request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=5)

                if str(response.status_code).startswith('3') \
                        and 'Location' in response.headers \
                        and response.headers['Location'].startswith(self._main_input.ngrok_url):
                    log_header_msg = f'FOUND REDIRECT! FILE: {self._main_input.output_filename}'
                    print(log_header_msg)
                    self.save_found(log_header_msg, [request], self._outputSsrfDir)

            except Exception as inst:
                print(inst)
                break

    def check_xxe(self, xxe_payloads: []):
        for request in xxe_payloads:
            request = f'{request}'.encode()
            try:
                response = requests_raw.raw(url=self._main_input.target_url,
                                            data=request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=5)

                web_page = response.text.lower()
                if response.status_code == 405:
                    continue
                if response.status_code == 500:
                    log_header_msg = f'Status: {response.status_code};' \
                                     f'DETAILS: {web_page[0:100]};' \
                                     f'MIME-TYPE: {response.headers["Content-Type"]};' \
                                     f'FILE: {self._main_input.output_filename}'
                    print(log_header_msg)
                    self.save_found(log_header_msg, [request], self._outputInjectionsDir)

                self.__xxe_keyword_checks(web_page, response, request)

            except:
                continue

    def save_found(self, log_header_msg, check_results: [], output_dir):
        if log_header_msg in self._found_headers:
            print(f'{log_header_msg} ALREADY ADDED')
            return

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        filename = f'{output_dir}/{self._main_input.output_filename}'

        with open(filename, 'a+') as f:
            replaced = log_header_msg.replace('\r', ' ').replace('\n', '')
            f.write(f"{replaced}\n\n")
            for request in check_results:
                if isinstance(request, str):
                    lines = list(filter(None, request.replace('\r', '').split('\n')))
                else:
                    lines = list(filter(None, request.decode('utf-8').replace('\r', '').split('\n')))
                for line in lines:
                    f.write(f"{line}\n")
                f.write(f"{' + ' * 10}\n")
            f.write(f"{'-' * 100}\n")
        f.close()
        self.is_found = True
        self._found_headers.add(log_header_msg)

    def injection_keyword_checks(self, web_page: str, response, request):
        for keyword in self._injections_to_check:
            if keyword in web_page \
                    and keyword not in self._main_input.first_resp.text.lower() \
                    and not any(word in web_page for word in self._false_positives):
                substr_index = web_page.find(keyword)
                start_index = substr_index - 50 if substr_index - 50 > 0 else 0
                last_index = substr_index + 50 if substr_index + 50 < len(web_page) else substr_index
                log_header_msg = f'INJECTION_FOUND: "{keyword}";' \
                                 f'STATUS: {response.status_code};' \
                                 f'DETAILS: {web_page[start_index:last_index]};' \
                                 f'MIME-TYPE: {response.headers["Content-Type"]};' \
                                 f'FILE: {self._main_input.output_filename}'
                print(log_header_msg)
                self.save_found(log_header_msg, [request], self._outputInjectionsDir)

    def __xxe_keyword_checks(self, web_page: str, response, request):
        for keyword in self._xxe_to_check:
            if keyword in web_page and keyword not in self._main_input.first_resp.text.lower() \
                    and not any(word in web_page for word in self._false_positives):
                substr_index = web_page.find(keyword)
                start_index = substr_index - 50 if substr_index - 50 > 0 else 0
                last_index = substr_index + 50 if substr_index + 50 < len(web_page) else substr_index
                log_header_msg = f'xxeFOUND: "{keyword}";' \
                                 f'STATUS: {response.status_code};' \
                                 f'DETAILS: {web_page[start_index:last_index]};' \
                                 f'MIME-TYPE: {response.headers["Content-Type"]};' \
                                 f'FILE: {self._main_input.output_filename}'
                print(log_header_msg)
                self.save_found(log_header_msg, [request], self._outputXxeDir)

    def check_bool_based_injections(self, bool_based_payloads):
        try:
            for bool_based_payload in bool_based_payloads:
                true_request = f'{bool_based_payload["TruePld"]}'.encode()
                false_request = f'{bool_based_payload["FalsePld"]}'.encode()
                true2_request = f'{bool_based_payload["True2Pld"]}'.encode()

                true_response = requests_raw.raw(url=self._main_input.target_url,
                                            data=true_request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=6)
                if not true_response:
                    return
                true_status = true_response.status_code
                if true_status == 403:
                    return

                true_length = len(true_response.text)
                if true_length == 0:
                    true_length = 1

                false_response = requests_raw.raw(url=self._main_input.target_url,
                                            data=false_request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=6)
                false_status = false_response.status_code
                false_length = len(false_response.text)
                if false_length == 0:
                    false_length = 1

                if abs(true_length - false_length) / true_length > self._bool_diff_rate:
                    true2_response = requests_raw.raw(url=self._main_input.target_url,
                                            data=true2_request,
                                            verify=False,
                                            allow_redirects=False,
                                            timeout=6)
                    true2_length = len(true2_response.text)
                    if true2_length == 0:
                        true2_length = 1

                    if abs(true_length - true2_length) / true_length < self._bool_diff_rate or true_length == true2_length:
                        msg = f"Bool sqli size FOUND! TRUE:{true_request[0:100]}; FALSE:{false_request[0:100]}"
                        print(msg)
                        self.save_found(msg, [true_request, false_request], self._outputBoolBasedDir)
                elif true_status != false_status:
                    true2_response = requests_raw.raw(url=self._main_input.target_url,
                                                      data=true2_request,
                                                      verify=False,
                                                      allow_redirects=False,
                                                      timeout=6)
                    true2_status = true2_response.status_code
                    if true_status == true2_status:
                        msg = f"Bool sqli status FOUND! TRUE:{true_request[0:100]}; FALSE:{false_request[0:100]}"
                        print(msg)
                        self.save_found(msg, [true_request, false_request], self._outputBoolBasedDir)

        except Exception as inst:
            print(f'Time based exception: {inst}')

    def check_time_based_injections(self, time_based_payloads):
        try:
            for time_based_payload in time_based_payloads:
                true_request = f'{time_based_payload["True"]}'.encode()
                false_request = f'{time_based_payload["False"]}'.encode()

                time_based_found1 = self.__send_time_based_request(true_request, with_delay=True)
                if time_based_found1:
                    time_based_found2 = self.__send_time_based_request(false_request, with_delay=False)
                    if time_based_found2:
                        time_based_found3 = self.__send_time_based_request(true_request, with_delay=True)
                        if time_based_found3:
                            time_based_found4 = self.__send_time_based_request(false_request, with_delay=False)
                            if time_based_found4:
                                time_based_found5 = self.__send_time_based_request(true_request, with_delay=True)
                                if time_based_found5:
                                    msg = f"Delay FOUND! TRUE:{true_request[0:100]}; " \
                                          f"FALSE:{false_request[0:100]}"
                                    print(msg)
                                    self.save_found(msg,
                                                    [true_request, false_request],
                                                    self._outputTimeBasedDir)

        except Exception as inst:
            print(f'Time based exception: {inst}')

    def __send_time_based_request(self, request, with_delay):
        try:
            response = requests_raw.raw(url=self._main_input.target_url,
                                        data=request,
                                        verify=False,
                                        allow_redirects=False,
                                        timeout=6)
            if response is not None and with_delay and response.elapsed.total_seconds() >= self._delay_in_seconds:
                return True
            if response is not None and not with_delay and response.elapsed.total_seconds() < self._delay_in_seconds:
                return True
            return False
        except (RequestException, ReadTimeoutError):
            return with_delay
