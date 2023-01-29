import urllib
from copy import deepcopy
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class RouteChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(RouteChecker, self).__init__(main_input)

    def run(self):
        injection_exploits = self.get_injection_payloads()
        self.check_injections(injection_exploits)

        idor_exploits = self.get_idor_payloads()
        self.check_idor(idor_exploits)

        ssti_exploits = self.get_ssti_payloads()
        self.check_ssti(ssti_exploits)

    def get_idor_payloads(self) -> []:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result = []

        for index, part in enumerate(route_parts):
            if part.isdigit():
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = str(int(part) - 1)
                first_idor_payload = f'/{"/".join(new_route_parts)}'
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = str(int(part) + 1)
                second_idor_payload = f'/{"/".join(new_route_parts)}'
                new_request_parts1 = deepcopy(request_parts)
                new_request_parts1[1] = first_idor_payload
                first_idor_request = ' '.join(new_request_parts1)
                new_request_parts2 = deepcopy(request_parts)
                new_request_parts2[1] = second_idor_payload
                second_idor_request = ' '.join(new_request_parts2)
                result.append([first_idor_request, second_idor_request])

        return result

    def get_ssti_payloads(self) -> []:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result = []

        for index, part in enumerate(route_parts):
            if part.isdigit():
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = str(int(part) + 1)
                first_idor_payload = f'/{"/".join(new_route_parts)}'
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = f'{part}+1'
                second_idor_payload = f'/{"/".join(new_route_parts)}'
                result.append([first_idor_payload, second_idor_payload])

        return result

    def get_injection_payloads(self) -> []:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result = []

        for index, part in enumerate(route_parts):
            for payload in self._injection_payloads:
                payload_part = f'{part}{payload}'
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = payload_part
                payload = f'/{"/".join(new_route_parts)}?{parsed.query}'
                request_parts[1] = payload
                result.append(' '.join(request_parts))

        return result

