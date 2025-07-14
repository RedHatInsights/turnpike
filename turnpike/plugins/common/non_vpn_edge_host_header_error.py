from requests.exceptions import InvalidHeader


class NonVPNEdgeHostHeaderError(InvalidHeader):
    pass
