import urllib
from http.cookies import SimpleCookie

from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class CookieChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(CookieChecker, self).__init__(main_input)

    def run(self):
        injection_exploits, idor_results, ssti_results, ssrf_results \
            = self.get_injection_payloads()

        self.check_injections(injection_exploits)
        self.check_idor(idor_results)
        self.check_ssti(ssti_results)
        self.check_ssrf(ssrf_results)

    def get_injection_payloads(self) -> []:
        injection_results = []
        idor_results = []
        ssti_results = []
        ssrf_results = []
        cookie_split = self._main_input.first_req.split('Cookie: ')

        if len(cookie_split) == 2:
            raw_cookies = cookie_split[1].split('\n')[0]
            cookie = SimpleCookie()
            cookie.load(raw_cookies)
            cookies = {}
            for key, morsel in cookie.items():
                cookies[key] = morsel.value

            for item in cookies:
                for payload in self._payloads:
                    original_str = f'{item}={cookies[item]}'
                    payload_str = f'{item}={payload}'
                    res = self._main_input.first_req.replace(original_str, payload_str)
                    injection_results.append(res)
                if str(cookies[item]).startswith('http'):
                    ssrf_payload = \
                        urllib.parse.quote(f'{self._main_input.ngrok_url}/cookie_{cookies[item]}',
                                           safe='')
                    original_str = f'{item}={cookies[item]}'
                    payload_str = f'{item}={ssrf_payload}'
                    res = self._main_input.first_req.replace(original_str, payload_str)
                    ssrf_results.append(res)
                if str(cookies[item]).isdigit():
                    original_str = f'{item}={cookies[item]}'
                    idor_str1 = f'{item}={str(int(cookies[item]) - 1)}'
                    idor_str2 = f'{item}={str(int(cookies[item]) + 1)}'
                    res1 = self._main_input.first_req.replace(original_str, idor_str1)
                    res2 = self._main_input.first_req.replace(original_str, idor_str2)
                    idor_results.append([res1, res2])

                    ssti_str1 = f'{item}={cookies[item]+1}'
                    ssti_str2 = f'{item}={str(int(cookies[item]) + 1)}'
                    res1 = self._main_input.first_req.replace(original_str, ssti_str1)
                    res2 = self._main_input.first_req.replace(original_str, ssti_str2)
                    ssti_results.append([res1, res2])

        return injection_results, idor_results, ssti_results, ssrf_results

