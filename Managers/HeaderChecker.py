from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class HeaderChecker(BaseChecker):
    def __init__(self, main_input: MainInput):
        super(HeaderChecker, self).__init__(main_input)
        self._known_headers = ['Host', 'Cookie', 'Accept', 'Content-Length',
                               'Accept-Language', 'Accept-Encoding',
                               'Content-Type', 'Sec-Fetch-Dest',
                               'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Te']

    def run(self):
        if self.severity == 1:
            self.__check_location_header()
        self.__check_xml_content_type()

        injection_payloads, time_based_payloads, bool_based_payloads = self.__get_headers_payloads()
        super().check_injections(injection_payloads)
        super().check_time_based_injections(time_based_payloads)
        super().check_bool_based_injections(bool_based_payloads)

    def __check_xml_content_type(self):
        for keyword in ['Content-Type: application/xml',
                        'Content-Type: text/xml',
                        'Content-Type: application/xhtml+xml']:
            if keyword in self._main_input.first_req:
                log_header_msg = f'xxeFOUND: "{keyword}";' \
                                 f'FILE: {self._main_input.output_filename}'
                print(log_header_msg)
                self.save_found(log_header_msg, [self._main_input.first_req], self._outputXxeDir)
                break

    def __check_location_header(self):
        split_body_req = self._main_input.first_req.split('\n\n', 1)

        body = ''
        if len(split_body_req) > 1:
            body = split_body_req[1]
        payload = f'{split_body_req[0]}\nLocation: {self._main_input.ngrok_url}\n\n{body}'

        super().check_ssrf([payload])

    def __get_headers_payloads(self) -> []:
        split_body_req = self._main_input.first_req.split('\n\n', 1)
        headers_dict = {pair[0]: pair[1] for pair in
                        [item.split(':', 1) for item in split_body_req[0].split('\n')[1:] if ':' in item]}

        new_headers = {header: headers_dict[header] for header in
                       [key for key in headers_dict if key not in self._known_headers]}

        injection_payloads = []
        time_based_payloads = []
        bool_based_payloads = []

        if new_headers:
            for key in new_headers:
                for payload in self._injection_payloads:
                    old = f'{key}:{new_headers[key]}'
                    new = f'{key}:{new_headers[key].strip('\r')}{payload}\r'
                    new_request = self._main_input.first_req.replace(old, new)
                    injection_payloads.append(new_request)

                for payload in self._time_based_payloads:
                    old = f'{key}:{new_headers[key]}'
                    true = f'{key}:{new_headers[key]}{payload["True"]}'
                    false = f'{key}:{new_headers[key]}{payload["False"]}'
                    new_true_request = self._main_input.first_req.replace(old, true)
                    new_false_request = self._main_input.first_req.replace(old, false)
                    time_based_payloads.append({'True': new_true_request,
                                                'False': new_false_request})

                for payload in self._bool_based_payloads:
                    old = f'{key}:{new_headers[key]}'
                    true = f'{key}:{new_headers[key]}{payload["TruePld"]}'
                    false = f'{key}:{new_headers[key]}{payload["FalsePld"]}'
                    true2 = f'{key}:{new_headers[key]}{payload["True2Pld"]}'
                    new_true_request = self._main_input.first_req.replace(old, true)
                    new_false_request = self._main_input.first_req.replace(old, false)
                    new_true2_request = self._main_input.first_req.replace(old, true2)
                    bool_based_payloads.append({'TruePld': new_true_request,
                                                'FalsePld': new_false_request,
                                                'True2Pld': new_true2_request})

        return injection_payloads, time_based_payloads, bool_based_payloads
