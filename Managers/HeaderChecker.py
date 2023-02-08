from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class HeaderChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(HeaderChecker, self).__init__(main_input)

    def run(self):
        self.__check_location_header()
        self.__check_xml_content_type()

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
        splitted_body_req = self._main_input.first_req.split('\n\n', 1)

        body = ''
        if len(splitted_body_req) > 1:
            body = splitted_body_req[1]
        payload = f'{splitted_body_req[0]}\nLocation: {self._main_input.ngrok_url}\n\n{body}'

        super().check_ssrf([payload])
