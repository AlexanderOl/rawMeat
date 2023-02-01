class Idor:
    def __init__(self, requests: [], param: str):
        self._requests = requests
        self._param = param

    @property
    def requests(self) -> []:
        return self._requests

    @property
    def param(self) -> []:
        return self._param
