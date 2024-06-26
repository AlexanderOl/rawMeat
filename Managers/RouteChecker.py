from urllib.parse import urlparse
from copy import deepcopy
from typing import List

from Models.Idor import Idor
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class RouteChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(RouteChecker, self).__init__(main_input)

    def run(self):
        injection_exploits = self.get_injection_payloads()
        super().check_injections(injection_exploits)

        if self.severity == 1:
            idor_payloads = self.get_idor_payloads()
            super().check_idor(idor_payloads)

        ssti_exploits = self.get_ssti_payloads()
        super().check_ssti(ssti_exploits)

    def get_idor_payloads(self) -> List[Idor]:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result: List[Idor] = []

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
                result.append(Idor([first_idor_request, second_idor_request],f'route part - {part}'))

        return result

    def get_ssti_payloads(self) -> []:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urlparse(route)
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
        parsed = urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result = []

        for index, part in enumerate(route_parts):
            for payload in self._injection_payloads:
                payload_part = f'{part}{payload}'
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = payload_part
                full_payload = f'/{"/".join(new_route_parts)}?{parsed.query}'
                request_parts[1] = full_payload
                result.append(' '.join(request_parts))
                if index == len(route_parts) - 1:
                    new_last_route_parts = deepcopy(route_parts)
                    last_payload_part = f'{part}?{payload}'
                    new_last_route_parts[index] = last_payload_part
                    payload = f'/{"/".join(new_last_route_parts)}{parsed.query}'
                    request_parts[1] = payload
                    result.append(' '.join(request_parts))
        return result

