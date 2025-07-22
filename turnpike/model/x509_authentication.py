from turnpike.model.authentication import Authentication


class X509Authentication(Authentication):

    def __init__(self, predicate: str):
        self.predicate = predicate
