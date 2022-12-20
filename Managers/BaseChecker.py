import os

import requests_raw
from Models.MainInput import MainInput


class BaseChecker:
    def __init__(self, main_input: MainInput):
        self._payloads = ['%27', '<poc>', '%22', '{{8*8}}poc']
        self._injections_to_check = [' syntax', '<poc>', '64poc', 'xpath', 'exception']
        self._xxe_to_check = ['syntax', 'root:', 'XXE found!', 'exception', '<foo>']
        self._outputIdorDir = 'Output/Idor'
        self._outputSstiDir = 'Output/Ssti'
        self._outputInjectionsDir = 'Output/Injections'
        self._outputXxeDir = 'Output/Xxe'
        self._main_input = main_input
        self.is_found = False

    def check_injections(self, route_exploits: []):

        for index, request in enumerate(route_exploits):
            request = f'{request}'.encode()
            try:
                response = requests_raw.raw(url=self._main_input.target_url,
                                            data=request,
                                            allow_redirects=False,
                                            timeout=5)

                web_page = response.text.lower()
                self.injection_keyword_checks(web_page, response.status_code, request)
                if str(response.status_code)[0] == '5':
                    print(f'500 Status: {response.status_code} - {request[0:100]}')
                    self.save_found([request], self._outputInjectionsDir)
            except:
                break

    def check_idor(self, idor_payloads: []):
        for idor_requests in idor_payloads:
            check_results = []
            for request in idor_requests:
                try:
                    response = requests_raw.raw(
                        url=self._main_input.target_url,
                        data=request.encode(),
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
                    print(f'FOUND IDOR - {idor_requests[0][0:100]}')
                    self.save_found(idor_requests, self._outputIdorDir)

    def check_ssti(self, ssti_payloads: []):
        for ssti_requests in ssti_payloads:
            check_results = []
            for request in ssti_requests:
                try:
                    response = requests_raw.raw(url=self._main_input.target_url,
                                                data=request.encode(),
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
                    print(f'FOUND SSTI - {ssti_requests[0][0:100]}')
                    self.save_found(ssti_requests, self._outputSstiDir)

    def check_ssrf(self, ssrf_payloads: []):
        for request in ssrf_payloads:
            request = f'{request}'.encode()
            try:
                requests_raw.raw(url=self._main_input.target_url,
                                 data=request,
                                 allow_redirects=False,
                                 timeout=5)
            except:
                break

    def check_xxe(self, xxe_payloads: []):
        for request in xxe_payloads:
            request = f'{request}'.encode()
            try:
                response = requests_raw.raw(url=self._main_input.target_url,
                                            data=request,
                                            allow_redirects=False,
                                            timeout=5)

                web_page = response.text.lower()
                self.xxe_keyword_checks(web_page, response.status_code, request)
                if str(response.status_code)[0] == '5':
                    print(f'Status:{response.status_code};'
                          f'DETAILS-{request[0:100]};'
                          f'SIZE-{len(web_page)};'
                          f'FILE-{self._main_input.output_filename}')
                    self.save_found([request], self._outputInjectionsDir)

            except:
                continue

    def save_found(self, check_results: [], output_dir):

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        filename = f'{output_dir}/{self._main_input.output_filename}'

        with open(filename, 'a+') as f:
            for request in check_results:
                if isinstance(request, str):
                    splitted = list(filter(None, request.split('\n')))
                else:
                    splitted = list(filter(None, request.decode('utf-8').split('\n')))
                for line in splitted:
                    f.write(f"{line}\n")
                f.write(f"{' + ' * 10}\n")
            f.write(f"{'-' * 100}\n")

        self.is_found = True

    def injection_keyword_checks(self, web_page: str, status_code: int, request):
        for keyword in self._injections_to_check:
            if keyword in web_page and keyword not in self._main_input.first_resp.text:
                substr_index = web_page.find(keyword)
                start_index = substr_index - 50 if substr_index - 50 > 0 else 0
                last_index = substr_index + 50 if substr_index + 50 < len(web_page) else substr_index
                print(f'injFOUND "{keyword}":'
                      f'STATUS-{status_code};'
                      f'DETAILS-{web_page[start_index:last_index]};'
                      f'SIZE-{len(web_page)};'
                      f'FILE-{self._main_input.output_filename}')
                self.save_found([request], self._outputInjectionsDir)

    def xxe_keyword_checks(self, web_page: str, status_code: int, request):
        for keyword in self._xxe_to_check:
            if keyword in web_page and keyword not in self._main_input.first_resp.text:
                substr_index = web_page.find(keyword)
                start_index = substr_index - 50 if substr_index - 50 > 0 else 0
                last_index = substr_index + 50 if substr_index + 50 < len(web_page) else substr_index
                print(f'xxeFOUND "{keyword}":'
                      f'STATUS-{status_code};'
                      f'DETAILS-{web_page[start_index:last_index]};'
                      f'SIZE-{len(web_page)};'
                      f'FILE-{self._main_input.output_filename}')
                self.save_found([request], self._outputXxeDir)
