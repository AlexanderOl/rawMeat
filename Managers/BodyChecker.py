import json
from urllib.parse import quote
import re
from typing import List
import regex
from copy import deepcopy

from Models.Idor import Idor
from Models.MainInput import MainInput
from Managers.BaseChecker import BaseChecker


class BodyChecker(BaseChecker):
    def __init__(self, main_input: MainInput):
        super().__init__(main_input)
        self._max_depth = 3
        self._json_pattern = regex.compile(r'\{(?:[^{}]|(?R))*\}')
        self._inject_result = []
        self._time_based_result = []
        self._bool_based_result = []
        self._idor_result: List[Idor] = []
        self._ssti_result = []
        self._ssrf_result = []
        self._xxe_result = []
        self._xxe_payload = '<!--?xml version="1.0" ?-->' \
                            '<!DOCTYPE replace [<!ENTITY name "XXE"> ]>' \
                            '<foo>&name; found!</foo>'

    def run(self):
        curr_depth = 1
        found_jsons = set(self._json_pattern.findall(self._main_input.first_req))
        if len(found_jsons) > 0:
            for found in found_jsons:
                self.__create_recursive_json_payloads(found, curr_depth)
        else:
            self.__create_body_payloads()

        self.__create_xxe_payloads()
        self.__create_multipart_payloads()

        super().check_injections(self._inject_result)

        super().check_time_based_injections(self._time_based_result)
        super().check_bool_based_injections(self._bool_based_result)

        super().check_ssti(self._ssti_result)
        super().check_xxe(self._xxe_result)

        if self.severity == 1:
            super().check_idor(self._idor_result)
            super().check_ssrf(self._ssrf_result)

    def __create_recursive_json_payloads(self, possible_json: str, curr_depth: int):

        if curr_depth >= self._max_depth:
            return
        curr_depth += 1

        try:
            replaced_str = re.sub(r'\bNone\b', 'null', possible_json)
            parsed_json = json.loads(replaced_str)
        except ValueError as e:
            try:
                replaced_str = replaced_str \
                    .replace('\'', '"') \
                    .replace('\\"', '"') \
                    .replace('"{', '{') \
                    .replace('}"', '}') \
                    .replace('False', 'false') \
                    .replace('True', 'true')
                parsed_json = json.loads(replaced_str)
            except ValueError as e:
                return

        for key in parsed_json:
            node_value = parsed_json[key]
            inner_found_jsons = set(self._json_pattern.findall(str(node_value)))
            if len(inner_found_jsons) == 0:

                if str(node_value).startswith('http'):
                    copy = deepcopy(parsed_json)
                    copy[key] = quote(f'{self._main_input.ngrok_url}/body_{key}', safe='')

                    str_json = json.dumps(copy)
                    self.__add_exploit(possible_json, str_json, self._ssrf_result)

                elif str(node_value).isdigit() or isinstance(node_value, float):
                    copy1 = deepcopy(parsed_json)
                    copy1[key] = str(int(copy1[key]) - 1)
                    str_json1 = json.dumps(copy1)
                    idor_twins = []
                    self.__add_exploit(possible_json, str_json1, idor_twins)

                    copy2 = deepcopy(parsed_json)
                    copy2[key] = str(int(copy2[key]) + 1)
                    str_json2 = json.dumps(copy2)
                    self.__add_exploit(possible_json, str_json2, idor_twins)

                    if len(idor_twins) == 2:
                        self._idor_result.append(Idor(idor_twins, key))

                    ssti_twins = []
                    copy1 = deepcopy(parsed_json)
                    copy1[key] = f'{copy1[key]}+1'
                    str_json1 = json.dumps(copy1)
                    self.__add_exploit(possible_json, str_json1, ssti_twins)

                    copy2 = deepcopy(parsed_json)
                    copy2[key] = str(int(copy2[key]) + 1)
                    str_json2 = json.dumps(copy2)
                    self.__add_exploit(possible_json, str_json2, ssti_twins)

                    if len(ssti_twins) == 2:
                        self._ssti_result.append(ssti_twins)

                for payload in self._injection_payloads:
                    copy = deepcopy(parsed_json)

                    if isinstance(copy[key], list):
                        if len(copy[key]) == 0:
                            copy[key].append(payload)
                        else:
                            copy[key][len(copy[key]) - 1] = f'{copy[key][len(copy[key]) - 1]}{payload}'
                    else:
                        if type(node_value) == bool or node_value is None or str(node_value).isdigit():
                            copy[key] = payload
                        else:
                            copy[key] = f'{copy[key]}{payload}'

                    str_json = json.dumps(copy)
                    self.__add_exploit(possible_json, str_json, self._inject_result)
            else:
                for inner_possible_json in inner_found_jsons:
                    inner_possible_json = inner_possible_json.replace("'", '"') \
                        .replace('"{', '{') \
                        .replace('}"', '}')
                    self.__create_recursive_json_payloads(inner_possible_json, curr_depth)

    def __add_exploit(self, old_json, new_json, result_list: []):

        exploit = None
        if old_json in self._main_input.first_req:
            exploit = self._main_input.first_req.replace(old_json, new_json)
        else:
            old = re.sub(r'\bNone\b', 'null', old_json)
            old = old \
                .replace(': ', ':') \
                .replace(', \'', ',\'') \
                .replace(', "', ',"') \
                .replace('False', 'false') \
                .replace('True', 'true') \
                .replace(': "{', ':"{') \
                .replace(': \'{', ':\'{')

            if old in self._main_input.first_req:
                new = new_json \
                    .replace(': \'', ':\'') \
                    .replace(': "', ':"') \
                    .replace('False', 'false') \
                    .replace('True', 'true') \
                    .replace(': "{', ':"{') \
                    .replace(': \'{', ':\'{')
                exploit = self._main_input.first_req.replace(old, new)
            elif old in self._main_input.first_req.replace('\\"', '"') \
                    .replace(':"{', ':{') \
                    .replace(' [', '[') \
                    .replace('}",', '},'):
                exploit = self._main_input.first_req.replace('\\"', '"') \
                    .replace(':"{', ':{') \
                    .replace('}",', '},') \
                    .replace(' [', '[')
                exploit.replace(old, new_json)
            else:
                first_10_chars_to_replace = self._main_input.first_req.find(new_json[:10])
                last_10_chars_to_replace = self._main_input.first_req.find(new_json[-10:])
                if first_10_chars_to_replace != -1 and first_10_chars_to_replace < last_10_chars_to_replace:
                    exploit = new_json.join([self._main_input.first_req[:first_10_chars_to_replace],
                                             self._main_input.first_req[last_10_chars_to_replace + 10:]])
                elif ' [' in new_json:
                    new_json = new_json.replace(' [', '[')
                    first_10_chars_to_replace = self._main_input.first_req.find(new_json[:10])
                    last_10_chars_to_replace = self._main_input.first_req.find(new_json[-10:])
                    if first_10_chars_to_replace < last_10_chars_to_replace:
                        exploit = new_json.join([self._main_input.first_req[:first_10_chars_to_replace],
                                                 self._main_input.first_req[last_10_chars_to_replace + 10:]])
                    else:
                        print(f'Need attention1 - {new_json}')
                else:
                    new_json_replace = new_json.replace(': \'', ':\'') \
                        .replace(': "', ':"') \
                        .replace(': "{', ':"{') \
                        .replace(': \'{', ':\'{')
                    first_10_chars_to_replace = self._main_input.first_req.find(new_json_replace[:10])
                    last_10_of_20_chars_to_replace = self._main_input.first_req.find(str(new_json_replace[-20:])[:10])
                    last_10_chars_to_replace = self._main_input.first_req.find(new_json_replace[-10:])
                    if first_10_chars_to_replace < last_10_chars_to_replace:
                        exploit = new_json_replace.join([self._main_input.first_req[:first_10_chars_to_replace],
                                                         self._main_input.first_req[last_10_chars_to_replace + 10:]])
                    elif first_10_chars_to_replace < last_10_of_20_chars_to_replace:
                        exploit = new_json_replace.join([self._main_input.first_req[:first_10_chars_to_replace],
                                                         self._main_input.first_req[
                                                         last_10_of_20_chars_to_replace + 15:]])
                    else:
                        print(f'Need attention2 - {new_json}')
        if exploit:
            result_list.append(exploit)
        else:
            print(f'CANT REPLACE - {new_json}')

    def __create_body_payloads(self):
        if '\n\n' not in self._main_input.first_req:
            return
        split_req = self._main_input.first_req.split('\n\n')
        body_params = split_req[1].strip('\r\n')
        params = filter(None, body_params.split("&"))
        for param in params:
            param_split = param.split('=')
            main_url_split = body_params.split(param)
            if '=' in param and str(param_split[1]).isdigit():
                first_idor_payload = str(int(param_split[1]) - 1)
                second_idor_payload = str(int(param_split[1]) + 1)
                self._idor_result.append(Idor([
                    f'{split_req[0]}\n\n{main_url_split[0]}{param_split[0]}={first_idor_payload}{main_url_split[1]}',
                    f'{split_req[0]}\n\n{main_url_split[0]}{param_split[0]}={second_idor_payload}{main_url_split[1]}'],
                    param_split[0]))

                first_ssti_payload = str(int(param_split[1]) + 1)
                second_ssti_payload = f'{param_split[1]}+1'
                self._ssti_result.append([
                    f'{split_req[0]}\n\n{main_url_split[0]}{param_split[0]}={first_ssti_payload}{main_url_split[1]}',
                    f'{split_req[0]}\n\n{main_url_split[0]}{param_split[0]}={second_ssti_payload}{main_url_split[1]}'])

            for payload in self._injection_payloads:
                if len(param_split) == 2:
                    param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                else:
                    param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                split_req[1] = f'{param_payload}\r\n'
                self._inject_result.append('\n\n'.join(split_req))

    def __create_multipart_payloads(self):
        if ('Content-Type: multipart/form-data' not in self._main_input.first_req
                or '-----------------------------' not in self._main_input.first_req):
            return
        split_req = self._main_input.first_req.split('-----------------------------')

        for n in range(len(split_req) - 2):
            if n == 0:
                continue

            for payload in self._time_based_payloads:
                true_payload = f'{split_req[n].rstrip("\n")}{payload["True"]}\n'
                false_payload = f'{split_req[n].rstrip("\n")}{payload["False"]}\n'
                true_res = self._main_input.first_req.replace(split_req[n], true_payload)
                false_res = self._main_input.first_req.replace(split_req[n], false_payload)
                self._time_based_result.append({'True': true_res, 'False': false_res})

            for payload in self._bool_based_payloads:
                true_payload = f'{split_req[n].rstrip("\n")}{payload["TruePld"]}\n'
                false_payload = f'{split_req[n].rstrip("\n")}{payload["FalsePld"]}\n'
                true2_payload = f'{split_req[n].rstrip("\n")}{payload["True2Pld"]}\n'
                true_res = self._main_input.first_req.replace(split_req[n], true_payload)
                false_res = self._main_input.first_req.replace(split_req[n], false_payload)
                true2_res = self._main_input.first_req.replace(split_req[n], true2_payload)
                self._bool_based_result.append(
                    {'TruePld': true_res, 'FalsePld': false_res, 'True2Pld': true2_res})

            for payload in self._injection_payloads:
                param_payload = f'{split_req[n].rstrip("\n")}{payload}'
                self._inject_result.append(self._main_input.first_req.replace(split_req[n], param_payload))

        body_params = split_req[1].strip('\r\n')
        params = filter(None, body_params.split("&"))
        for param in params:
            param_split = param.split('=')
            main_url_split = body_params.split(param)
            if str(param_split[1]).isdigit():
                first_ssti_payload = str(int(param_split[1]) + 1)
                second_ssti_payload = f'{param_split[1]}+1'
                self._ssti_result.append([
                    f'{main_url_split[0]}{param_split[0]}={first_ssti_payload}{main_url_split[1]}',
                    f'{main_url_split[0]}{param_split[0]}={second_ssti_payload}{main_url_split[1]}'])
            for payload in self._injection_payloads:
                if len(param_split) == 2:
                    param_payload = f'{main_url_split[0]}{param_split[0]}={param_split[1]}{payload}{main_url_split[1]}'
                else:
                    param_payload = f'{main_url_split[0]}{param_split[0]}{payload}{main_url_split[1]}'
                split_req[1] = f'{param_payload}\r\n'
                self._inject_result.append('\n\n'.join(split_req))

    def __create_xxe_payloads(self):
        split_verb_req = self._main_input.first_req.split(' ', 1)

        if split_verb_req[0] == 'GET':
            split_verb_req[0] = 'POST'

        split_body_req = split_verb_req[1].split('\n\n', 1)

        if 'Content-Type:' in split_body_req[0]:
            split = split_body_req[0].split('Content-Type:', 1)
            second_part = split[1].split('\n', 1)
            xxe_payload = f'{split_verb_req[0]} {split[0]}Content-Type: application/xml\n{second_part[1]}\n\n{self._xxe_payload}'
            self._xxe_result.append(xxe_payload)

        else:
            self._xxe_result.append(
                f'{split_verb_req[0]} {split_body_req[0]}\nContent-Type: application/xml\n\n{self._xxe_payload}')
