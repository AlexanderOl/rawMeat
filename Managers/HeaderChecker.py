from Managers.BaseChecker import BaseChecker
from Models.MainInput import MainInput


class HeaderChecker(BaseChecker):
    def __int__(self, main_input: MainInput):
        super(HeaderChecker, self).__init__(main_input)

    def run(self):
        for keyword in ['Content-Type: application/xml',
                        'Content-Type: text/xml',
                        'Content-Type: application/xhtml+xml']:
            if keyword in self._main_input.first_req:
                log_header_msg = f'xxeFOUND: "{keyword}";' \
                                 f'FILE: {self._main_input.output_filename}'
                print(log_header_msg)
                self.save_found(log_header_msg, [self._main_input.first_req], self._outputXxeDir)
                break





