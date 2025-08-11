from turnpike.model.authentication import Authentication


class SAMLAuthentication(Authentication):

    def __init__(self, predicate: str):
        self.predicate: str = predicate
