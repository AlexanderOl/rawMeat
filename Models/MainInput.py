
class MainInput:
    def __init__(self, target_url: str,
                 first_req: bytes,
                 first_resp,
                 output_filename: str,
                 ngrok_url: str):
        self._target_url = target_url
        self._first_req = first_req.decode('utf-8')
        self._first_resp = first_resp
        self._output_filename = output_filename
        self._ngrok_url = ngrok_url

    @property
    def target_url(self) -> str:
        return self._target_url

    @property
    def first_req(self) -> str:
        return str(self._first_req)

    @property
    def first_resp(self):
        return self._first_resp

    @property
    def output_filename(self) -> str:
        return str(self._output_filename)

    @property
    def ngrok_url(self) -> str:
        return str(self._ngrok_url)
