from turnpike.plugin import TurnpikePlugin, PolicyContext


class MockPlugin(TurnpikePlugin):
    """Mock plugin is just a plugin that captures the matched backend by Turnpike."""

    def __init__(self, app):
        super().__init__(app)
        self.matched_backend = None

    def process(self, context: PolicyContext):
        self.matched_backend = context.backend

        return context
