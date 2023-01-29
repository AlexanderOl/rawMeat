import urllib
from copy import deepcopy

from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class ParamChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(ParamChecker, self).__init__(main_input)

    def run(self):
        injection_payloads = self.__get_injection_param_payloads()
        super().check_injections(injection_payloads)

        time_based_payloads = self.__get_time_based_param_payloads()
        super().check_time_based_injections(time_based_payloads)

        idor_payloads = self.__get_idor_param_payloads()
        super().check_idor(idor_payloads)

        ssti_exploits = self.__get_ssti_param_payloads()
        super().check_ssti(ssti_exploits)

        ssrf_exploits = self.get_ssrf_param_payloads()
        super().check_ssrf(ssrf_exploits)

    def __get_injection_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            for payload in self._injection_payloads:
                main_url_split = route.split(param)
                param_split = param.split('=')
                if len(param_split) == 2:
                    param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                else:
                    param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                request_parts[1] = param_payload
                result.append(' '.join(request_parts))

        return result

    def __get_time_based_param_payloads(self) -> [{}]:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            for payload in self._time_based_payloads:
                main_url_split = route.split(param)
                param_split = param.split('=')
                if len(param_split) == 2:
                    true_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload["True"]}{main_url_split[1]}'
                    false_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload["False"]}{main_url_split[1]}'
                    payloads = {'True':true_payload, 'False':false_payload}
                else:
                    true_payload = f'{main_url_split[0]}{param_split[0]}{payload["True"]}{main_url_split[1]}'
                    false_payload = f'{main_url_split[0]}{param_split[0]}{payload["False"]}{main_url_split[1]}'
                    payloads = {'True': true_payload, 'False': false_payload}
                copy = deepcopy(request_parts)
                request_parts[1] = payloads['True']
                copy[1] = payloads['False']
                result.append({'True': ' '.join(request_parts), 'False': ' '.join(copy)})

        return result

    def __get_idor_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            param_split = param.split('=')
            if len(param_split) == 2:
                possible_int_param_value = str(param_split[1])
            else:
                possible_int_param_value = str(param_split[0])

            if possible_int_param_value.isdigit():
                first_idor_payload = str(int(possible_int_param_value) - 1)
                second_idor_payload = str(int(possible_int_param_value) + 1)
                main_url_split = self._main_input.first_req.split(param, 1)
                if len(param_split) == 2:
                    result.append([
                        f'{main_url_split[0]}{param_split[0]}={first_idor_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{param_split[0]}={second_idor_payload}{main_url_split[1]}'])
                else:
                    result.append([
                        f'{main_url_split[0]}{first_idor_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{second_idor_payload}{main_url_split[1]}'])

        return result

    def __get_ssti_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            param_split = param.split('=')
            if len(param_split) == 2:
                possible_int_param_value = str(param_split[1])
            else:
                possible_int_param_value = str(param_split[0])

            if possible_int_param_value.isdigit():
                first_ssti_payload = str(int(possible_int_param_value) + 1)
                second_ssti_payload = f'{possible_int_param_value}+1'
                main_url_split = self._main_input.first_req.split(param, 1)
                if len(param_split) == 2:
                    result.append([
                        f'{main_url_split[0]}{param_split[0]}={first_ssti_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{param_split[0]}={second_ssti_payload}{main_url_split[1]}'])
                else:
                    result.append([
                        f'{main_url_split[0]}{first_ssti_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{second_ssti_payload}{main_url_split[1]}'])

        return result

    def get_ssrf_param_payloads(self) -> []:
        result = []
        request_parts = self._main_input.first_req.split(' ')
        route = request_parts[1]
        parsed = urllib.parse.urlparse(route)
        params = filter(None, parsed.query.split("&"))

        for param in params:
            param_split = param.split('=')
            if len(param_split) == 2:
                possible_int_param_value = str(param_split[1])
            else:
                possible_int_param_value = str(param_split[0])

            if possible_int_param_value.startswith('http'):
                ssrf_payload = urllib.parse.quote(f'{self._main_input.ngrok_url}/param_{param_split[0]}', safe='')
                main_url_split = self._main_input.first_req.split(param, 1)
                if len(param_split) == 2:
                    result.append(f'{main_url_split[0]}{param_split[0]}={ssrf_payload}{main_url_split[1]}')
                else:
                    result.append(f'{main_url_split[0]}{ssrf_payload}{main_url_split[1]}')

        return result
