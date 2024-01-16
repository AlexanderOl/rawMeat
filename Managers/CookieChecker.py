from urllib.parse import quote
from http.cookies import SimpleCookie
from typing import List

from Managers.BaseChecker import BaseChecker
from Models.Idor import Idor
from Models.MainInput import MainInput


class CookieChecker(BaseChecker):
    def __init__(self, main_input: MainInput):
        super(CookieChecker, self).__init__(main_input)
        self._checked_hosts = set()

    def run(self):

        checked_host = self._check_header_host()
        if not checked_host:
            print(f'Host: {checked_host} is already checked')
            return
        injection_exploits, idor_results, ssti_results, ssrf_results, bool_based_result, time_based_result \
            = self.get_injection_payloads()

        self.check_injections(injection_exploits)
        super().check_idor(idor_results)
        self.check_ssti(ssti_results)
        self.check_ssrf(ssrf_results)
        self.check_bool_based_injections(bool_based_result)
        self.check_time_based_injections(time_based_result)

    def _check_header_host(self):
        split_body_req = self._main_input.first_req.split('\n\n', 1)
        headers_dict = {pair[0]: pair[1] for pair in
                        [item.split(':', 1) for item in split_body_req[0].split('\n')[1:] if ':' in item]}
        host = headers_dict['Host']
        if host in self._checked_hosts:
            return

        self._checked_hosts.add(host)
        return True

    def get_injection_payloads(self) -> []:
        injection_results = []
        idor_results: List[Idor] = []
        ssti_results = []
        ssrf_results = []
        bool_based_result = []
        time_based_result = []
        cookie_split = self._main_input.first_req.split('Cookie: ')

        if len(cookie_split) == 2:
            raw_cookies = cookie_split[1].split('\n')[0]
            cookie = SimpleCookie()
            cookie.load(raw_cookies)
            cookies = {}
            for key, morsel in cookie.items():
                cookies[key] = morsel.value

            for item in cookies:
                for payload in self._injection_payloads:
                    original_str = f'{item}={cookies[item]}'
                    payload_str = f'{item}={payload}'
                    res = self._main_input.first_req.replace(original_str, payload_str)
                    injection_results.append(res)

                for payload in self._bool_based_payloads:
                    original_str = f'{item}={cookies[item]}'
                    true_payload = f'{item}={payload["TruePld"]}'
                    true_res = self._main_input.first_req.replace(original_str, true_payload)
                    false_payload = f'{item}={payload["FalsePld"]}'
                    false_res = self._main_input.first_req.replace(original_str, false_payload)
                    true2_payload = f'{item}={payload["True2Pld"]}'
                    true2_res = self._main_input.first_req.replace(original_str, true2_payload)
                    bool_based_result.append(
                        {'TruePld': true_res, 'FalsePld': false_res, 'True2Pld': true2_res})

                for payload in self._time_based_payloads:
                    original_str = f'{item}={cookies[item]}'
                    true_payload = f'{item}={payload["True"]}'
                    true_res = self._main_input.first_req.replace(original_str, true_payload)
                    false_payload = f'{item}={payload["False"]}'
                    false_res = self._main_input.first_req.replace(original_str, false_payload)
                    time_based_result.append({'True': true_res, 'False': false_res})

                if str(cookies[item]).startswith('http') or str(cookies[item]).startswith('/'):
                    ssrf_payload = \
                        quote(f'{self._main_input.ngrok_url}/cookie_{cookies[item]}', safe='')
                    original_str = f'{item}={cookies[item]}'
                    payload_str = f'{item}={ssrf_payload}'
                    res = self._main_input.first_req.replace(original_str, payload_str)
                    ssrf_results.append(res)
                if str(cookies[item]).isdigit():
                    original_str = f'{item}={cookies[item]}'
                    idor_str1 = f'{item}={str(int(cookies[item]) - 1)}'
                    idor_str2 = f'{item}={str(int(cookies[item]) + 1)}'
                    idor_res1 = self._main_input.first_req.replace(original_str, idor_str1)
                    idor_res2 = self._main_input.first_req.replace(original_str, idor_str2)
                    idor_results.append(Idor([idor_res1, idor_res2], item))

                    ssti_str1 = f'{item}={cookies[item]}+1'
                    ssti_str2 = f'{item}={str(int(cookies[item]) + 1)}'
                    ssti_res1 = self._main_input.first_req.replace(original_str, ssti_str1)
                    ssti_res2 = self._main_input.first_req.replace(original_str, ssti_str2)
                    ssti_results.append([ssti_res1, ssti_res2])

        return injection_results, idor_results, ssti_results, ssrf_results, bool_based_result, time_based_result
