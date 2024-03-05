import os.path
import uuid
import requests
from requests import Timeout
from requests.exceptions import InvalidHeader

from urllib3 import disable_warnings, exceptions


class RequestHelper:
    def __init__(self, url: str):
        self._url = url.rstrip('/')
        self._err_directory = 'Errors'
        disable_warnings(exceptions.InsecureRequestWarning)

    def request_raw(self, raw_request: str):

        method = raw_request.split(' ', 1)[0]
        curr_url = f'{self._url}{raw_request.split(' ', 2)[1]}'

        body_split = []
        if '\n\n' in raw_request:
            body_split = raw_request.split('\n\n')
        elif '\r\n\r\n' in raw_request:
            body_split = raw_request.split('\r\n\r\n')

        body_data = None
        if len(body_split) == 0:
            return
        elif len(body_split) == 2:
            body_data = body_split[1].encode()

        headers_list = body_split[0].strip().split('\n')

        headers_dict = {}
        for index, header in enumerate(headers_list):
            if index < 2 or ': ' not in header:
                continue
            name, value = header.split(': ', 1)
            headers_dict[name] = str(value).rstrip('\r')

        try:
            resp = requests.request(method=method,
                                    url=curr_url,
                                    headers=headers_dict,
                                    data=body_data,
                                    verify=False,
                                    timeout=10,
                                    allow_redirects=False)

            if resp.status_code == 400:
                print(f'400 ERROR! {resp.text}')
                if not os.path.exists(self._err_directory):
                    os.makedirs(self._err_directory)
                filename = f'{self._err_directory}/{str(uuid.uuid4())[:8]}.txt'
                lines = list(filter(None, raw_request.replace('\r', '').split('\n')))
                with open(filename, 'a+') as f:
                    for line in lines:
                        f.write(f"{line}\n")
                    f.close()
            else:
                print(f'Status: {resp.status_code}')
            return resp

        except (ConnectionError, Timeout, InvalidHeader):
            print(f'Url ({curr_url}) - Timeout, ConnectionError, InvalidHeader')
            return

