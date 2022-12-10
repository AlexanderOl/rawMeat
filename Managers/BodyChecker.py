import json
import urllib

import regex
from copy import deepcopy
from collections.abc import Iterable
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class BodyChecker(BaseChecker):
    def __init__(self, main_input: MainInput):
        super().__init__(main_input)
        self._json_dive_level = 3
        self._json_pattern = regex.compile(r'\{(?:[^{}]|(?R))*\}')
        self._inject_result = []
        self._idor_result = []
        self._ssti_result = []
        self._ssrf_result = []

    def create_recursive_json_payloads(self, possible_json: str):
        replaced_str = possible_json \
            .replace('\'', '"') \
            .replace('\\"', '"') \
            .replace('"{', '{') \
            .replace('}"', '}') \
            .replace('False', 'false') \
            .replace('True', 'true')

        try:
            parsed_json = json.loads(replaced_str)
        except ValueError as e:
            return

        for key in parsed_json:
            node_value = parsed_json[key]
            inner_found_jsons = set(self._json_pattern.findall(str(node_value)))
            if len(inner_found_jsons) == 0:

                if str(node_value).startswith('http'):
                    copy = deepcopy(parsed_json)
                    copy[key] = urllib.parse.quote(
                        f'{self._main_input.ngrok_url}/body_{key}', safe='')

                    str_json = json.dumps(copy)
                    self.add_exploit(possible_json, str_json, self._ssrf_result)

                elif str(node_value).isdigit():
                    copy1 = deepcopy(parsed_json)
                    copy1[key] = str(int(copy1[key]) - 1)
                    str_json1 = json.dumps(copy1)
                    idor_twins = []
                    self.add_exploit(possible_json, str_json1, idor_twins)

                    copy2 = deepcopy(parsed_json)
                    copy2[key] = str(int(copy2[key]) + 1)
                    str_json2 = json.dumps(copy2)
                    self.add_exploit(possible_json, str_json2, idor_twins)

                    if len(idor_twins) == 2:
                        self._idor_result.append(idor_twins)

                    ssti_twins = []
                    copy1 = deepcopy(parsed_json)
                    copy1[key] = f'{copy1[key]}+1'
                    str_json1 = json.dumps(copy1)
                    self.add_exploit(possible_json, str_json1, ssti_twins)

                    copy2 = deepcopy(parsed_json)
                    copy2[key] = str(int(copy2[key]) + 1)
                    str_json2 = json.dumps(copy2)
                    self.add_exploit(possible_json, str_json2, ssti_twins)

                    if len(ssti_twins) == 2:
                        self._ssti_result.append(ssti_twins)

                elif type(node_value) == bool or node_value is None:
                    continue

                else:
                    for payload in self._payloads:
                        copy = deepcopy(parsed_json)

                        if isinstance(copy[key], list):
                            if len(copy[key]) == 0:
                                copy[key].append(payload)
                            else:
                                copy[key][len(copy[key])-1] = f'{copy[key][len(copy[key])-1]}{payload}'
                        else:
                            copy[key] += payload

                        str_json = json.dumps(copy)
                        self.add_exploit(possible_json, str_json, self._inject_result)
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
        self.check_ssti(self._ssti_result)
        self.check_ssrf(self._ssrf_result)

    def add_exploit(self, old_json, new_json, result_list: []):

        exploit = None
        if old_json in self._main_input.first_req:
            exploit = self._main_input.first_req.replace(old_json, new_json)
        else:
            old = old_json\
                .replace('\'', '"')\
                .replace(', ',',')\
                .replace(': ',':')\
                .replace('False', 'false')\
                .replace('True', 'true')\
                .replace(':"{', ':"{')
            if old in self._main_input.first_req:
                new = new_json\
                    .replace('\'', '"')\
                    .replace(', ', ',')\
                    .replace(': ', ':')\
                    .replace('False', 'false')\
                    .replace('True', 'true')
                exploit = self._main_input.first_req.replace(old, new)
            elif old in self._main_input.first_req.replace('\\"', '"') \
                    .replace(':"{', ':{') \
                    .replace('}",', '},'):
                print(f'Unable to parse - {new_json}')
                return
            else:
                first_10_chars_to_replace = self._main_input.first_req.find(new_json[:10])
                last_10_chars_to_replace = self._main_input.first_req.find(new_json[-10:])
                if first_10_chars_to_replace < last_10_chars_to_replace:
                    exploit = old.join([self._main_input.first_req[:first_10_chars_to_replace],
                                        self._main_input.first_req[last_10_chars_to_replace+10:]])
                else:
                    print(f'Need attention- {new_json}')

        if exploit:
            result_list.append(exploit)
        else:
            print(f'CANT REPLACE - {new_json}')

    def create_body_payloads(self):
        splitted_req = self._main_input.first_req.split('\n\n')
        if len(splitted_req) == 2:
            body_params = splitted_req[1].strip('\r\n')
            params = filter(None, body_params.split("&"))
            for param in params:
                param_split = param.split('=')
                main_url_split = body_params.split(param)
                if str(param_split[1]).isdigit():
                    first_idor_payload = str(int(param_split[1]) - 1)
                    second_idor_payload = str(int(param_split[1]) + 1)
                    self._idor_result.append([
                        f'{main_url_split[0]}{param_split[0]}={first_idor_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{param_split[0]}={second_idor_payload}{main_url_split[1]}'])

                    first_ssti_payload = str(int(param_split[1]) + 1)
                    second_ssti_payload = f'{param_split[1]}+1'
                    self._ssti_result.append([
                        f'{main_url_split[0]}{param_split[0]}={first_ssti_payload}{main_url_split[1]}',
                        f'{main_url_split[0]}{param_split[0]}={second_ssti_payload}{main_url_split[1]}'])
                else:
                    for payload in self._payloads:
                        if len(param_split) == 2:
                            param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                        else:
                            param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                        splitted_req[1] = f'{param_payload}\r\n'
                        self._inject_result.append('\n\n'.join(splitted_req))
