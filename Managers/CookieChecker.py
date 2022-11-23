from http.cookies import SimpleCookie

from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class CookieChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(CookieChecker, self).__init__(main_input)

    def run(self):
        route_exploits = self.get_route_payloads()
        self.check_injections(route_exploits)

    def get_route_payloads(self) -> []:
        injection_results = []
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

        return injection_results

