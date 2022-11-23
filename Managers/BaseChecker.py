import os

import requests_raw
from Models.MainInput import MainInput


class BaseChecker:
    def __init__(self, main_input: MainInput):
        self._payloads = ['%27', '<poc>', '%22', '{{8*8}}poc']
        self._keywords_to_check = [' syntax ', '<poc>', '64poc']
        self._outputIdorDir = 'Output/Idor'
        self._outputInjectionsDir = 'Output/Injections'
        self._main_input = main_input

    def check_idor(self, idor_payloads: []):
        if self._main_input.first_resp.status_code < 400:
            for idor_requests in idor_payloads:
                check_results = []
                for request in idor_requests:
                    request = f'{request}'.encode()
                    response = requests_raw.raw(url=self._main_input.target_url, data=request, allow_redirects=False)
                    if response.status_code != self._main_input.first_resp.status_code:
                        check_results = []
                        break
                    check_results.append(response)

                if len(check_results) == len(idor_requests):
                    responses_length = [len(response.text) for response in check_results]
                    responses_length.append(len(self._main_input.first_resp.text))
                    if len(responses_length) == len(set(responses_length)):
                        print(f'FOUND IDOR - {idor_requests[0][0:100]}')
                        self.save_found(idor_requests, self._outputIdorDir)

    def save_found(self, check_results: [], output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        filename = f'{output_dir}/{self._main_input.output_filename}'
        with open(filename, 'w+') as f:
            for request in check_results:
                str_request = request.decode('utf-8')
                splitted = list(filter(None, str_request.split('\n')))
                for line in splitted:
                    f.write(f"{line}\n")
                f.write(f"{' + ' * 10}\n")
            f.write(f"{'-' * 100}\n")

    def check_injections(self, route_exploits: []):
        for index, request in enumerate(route_exploits):
            request = f'{request}'.encode()
            response = requests_raw.raw(url=self._main_input.target_url, data=request, allow_redirects=False)
            if response.status_code < 300:
                web_page = response.text.lower()
                self.keyword_checks(web_page, response.status_code, request)
            elif str(response.status_code)[0] == '5':
                print(f'FOUND: {response.status_code} - {request[0:100]}')
                self.save_found([request], self._outputInjectionsDir)

    def keyword_checks(self, web_page: str, status_code: int, request):
        for keyword in self._keywords_to_check:
            if keyword in web_page:
                substr_index = web_page.find(keyword)
                start_index = substr_index - 50 if substr_index - 50 > 0 else 0
                last_index = substr_index + 50 if substr_index + 50 < len(web_page) else substr_index
                print(f'FOUND "{keyword}": {status_code} - {web_page[start_index:last_index]}')
                self.save_found([request], self._outputInjectionsDir)
