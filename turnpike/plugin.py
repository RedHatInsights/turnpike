class TurnpikePlugin:
    def __init__(self, app):
        self.app = app

    def register_blueprint(self):
        pass

    def process(self, context):
        raise NotImplementedError()


class TurnpikeAuthPlugin:
    name = "unnamed"

    def __init__(self, app):
        self.app = app

    def register_blueprint(self):
        pass

    def process(self, backend, context):
        raise NotImplementedError()

    def login_url(self):
        return None
