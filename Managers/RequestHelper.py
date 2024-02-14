import uuid
import requests_raw

from urllib3 import disable_warnings, exceptions


class RequestHelper:
    def __init__(self, url: str):
        self._url = url
        disable_warnings(exceptions.InsecureRequestWarning)

    def request_raw(self, raw_request: str):
        encoded = f'{raw_request.replace('\n', '\r\n').replace('\r\r\n','\r\n')}\r\n\r\n'.encode()
        resp = requests_raw.raw(url=self._url,
                                data=encoded,
                                allow_redirects=False,
                                timeout=10,
                                verify=False)
        if resp.status_code == 400:
            print(f'400 ERROR! {resp.text}')
            filename = f'Errors/{str(uuid.uuid4())[:8]}.txt'
            lines = list(filter(None, raw_request.replace('\r', '').split('\n')))
            with open(filename, 'a+') as f:
                for line in lines:
                    f.write(f"{line}\n")
                f.close()
        else:
            print(f'Status: {resp.status_code}')

        return resp
