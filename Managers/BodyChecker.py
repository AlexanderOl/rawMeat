import json
import regex
from copy import deepcopy
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class BodyChecker(BaseChecker):
    def __init__(self, main_input: MainInput):
        super().__init__(main_input)
        self._json_dive_level = 3
        self._json_pattern = regex.compile(r'\{(?:[^{}]|(?R))*\}')
        self._inject_result = []
        self._idor_result = []

    def create_recursive_json_payloads(self, possible_json: str):
        replaced_str = possible_json \
            .replace('\'', '"') \
            .replace('\\"', '"') \
            .replace('"{', '{') \
            .replace('}"', '}') \
            .replace('False', 'false') \
            .replace('True', 'true')

        parsed_json = json.loads(replaced_str)

        for key in parsed_json:
            node_value = parsed_json[key]
            inner_found_jsons = set(self._json_pattern.findall(str(node_value)))
            if len(inner_found_jsons) == 0:

                if str(node_value).isdigit():
                    copy1 = deepcopy(parsed_json)
                    copy1[key] = str(int(copy1[key]) - 1)
                    str_json1 = json.dumps(copy1)
                    idor_twins = []
                    self.add_exploit(possible_json, str_json1, idor_twins)

                    copy2 = deepcopy(parsed_json)
                    copy2[key] = str(int(copy2[key]) - 2)
                    str_json2 = json.dumps(copy2)
                    self.add_exploit(possible_json, str_json2, idor_twins)

                    if len(idor_twins) == 2:
                        self._idor_result.append(idor_twins)

                elif type(node_value) != bool:

                    for payload in self._payloads:
                        copy = deepcopy(parsed_json)
                        copy[key] += payload
                        str_json = json.dumps(copy)
                        search_possible_json = str(possible_json)
                        self.add_exploit(search_possible_json, str_json, self._inject_result)
            else:
                for inner_possible_json in inner_found_jsons:
                    self.create_recursive_json_payloads(inner_possible_json)

    def run(self):
        found_jsons = set(self._json_pattern.findall(self._main_input.first_req))
        if len(found_jsons)>0:
            for found in found_jsons:
                self.create_recursive_json_payloads(found)
        else:
            self.create_body_payloads()

        self.check_injections(self._inject_result)

        self.check_idor(self._idor_result)

    def add_exploit(self, replaced_json, str_json, result_list: []):

        exploit = None
        if replaced_json in self._main_input.first_req:
            exploit = self._main_input.first_req.replace(replaced_json, str_json)
        else:
            old = replaced_json\
                .replace('\'', '"')\
                .replace(', ',',')\
                .replace(': ',':')\
                .replace('False', 'false')\
                .replace('True', 'true')\
                .replace(':"{', ':"{')
            if old in self._main_input.first_req:
                new = str_json\
                    .replace('\'', '"')\
                    .replace(', ', ',')\
                    .replace(': ', ':')\
                    .replace('False', 'false')\
                    .replace('True', 'true')
                exploit = self._main_input.first_req.replace(old, new)
            elif old in self._main_input.first_req.replace('\\"', '"') \
                    .replace(':"{', ':{') \
                    .replace('}",', '},'):
                print(f'Unable to parse - {str_json}')
                return
            else:
                print(f'Need attention- {str_json}')

        if exploit:
            result_list.append(exploit)
        else:
            print(f'CANT REPLACE - {str_json}')

    def create_body_payloads(self):
        splitted_req = self._main_input.first_req.split('\n\n')
        if len(splitted_req) > 1:
            body_params = splitted_req[1].strip('\r\n')
            params = filter(None, body_params.split("&"))
            for param in params:
                param_split = param.split('=')
                main_url_split = body_params.split(param)
                if str(param_split[1]).isdigit():
                    first_idor_payload = str(int(param_split[1]) - 1)
                    second_idor_payload = str(int(param_split[1]) - 2)
                    self._idor_result.append([
                        f'{main_url_split[0]}{param_split[0]}={first_idor_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{param_split[0]}={second_idor_payload}{main_url_split[1]}'])
                else:
                    for payload in self._payloads:
                        if len(param_split) == 2:
                            param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                        else:
                            param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                        splitted_req[1] = f'{param_payload}\r\n'
                        self._inject_result.append('\n\n'.join(splitted_req))
