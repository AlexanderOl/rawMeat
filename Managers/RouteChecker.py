import urllib
from copy import deepcopy
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class RouteChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(RouteChecker, self).__init__(main_input)

    def run(self):
        route_exploits = self.get_route_payloads()
        self.check_injections(route_exploits)

        route_params_payloads = self.get_param_payloads()
        self.check_injections(route_params_payloads)

        route_idor_exploits = self.get_idor_route_payloads()
        self.check_idor(route_idor_exploits)

        param_idor_payloads = self.get_idor_param_payloads()
        self.check_idor(param_idor_payloads)

    def get_idor_route_payloads(self) -> []:
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
                new_route_parts[index] = str(int(part) - 2)
                second_idor_payload = f'/{"/".join(new_route_parts)}'
                result.append([first_idor_payload, second_idor_payload])

        return result

    def get_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            for payload in self._payloads:
                main_url_split = route.split(param)
                param_split = param.split('=')
                if len(param_split) == 2:
                    param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                else:
                    param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                request_parts[1] = param_payload
                result.append(' '.join(request_parts))

        return result

    def get_idor_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            param_split = param.split('=')
            if str(param_split[1]).isdigit():
                first_idor_payload = str(int(param_split[1]) - 1)
                second_idor_payload = str(int(param_split[1]) - 2)
                main_url_split = self._main_input.first_req.split(param)
                result.append([
                    f'{main_url_split[0]}{param_split[0]}={first_idor_payload}{main_url_split[1]}',
                    f'{main_url_split[0]}{param_split[0]}={second_idor_payload}{main_url_split[1]}'])

        return result

    def get_route_payloads(self) -> []:
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        route_parts = [r for r in parsed.path.split('/') if r.strip()]
        result = []

        for index, part in enumerate(route_parts):
            for payload in self._payloads:
                payload_part = f'{part}{payload}'
                new_route_parts = deepcopy(route_parts)
                new_route_parts[index] = payload_part
                payload = f'/{"/".join(new_route_parts)}?{parsed.query}'
                request_parts[1] = payload
                result.append(' '.join(request_parts))

        return result

