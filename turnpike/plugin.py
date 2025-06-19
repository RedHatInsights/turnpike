class PolicyContext:
    """
    PolicyContext represents the policy evaluation context for a particular
    request handled by `turnpike.view.policy_view`. Plugins processing a
    request will receive a PolicyContext object, have the ability to modify it,
    and return it for processing by additional plugins.

    This is a dataclass with several attributes.

    * `backend` represents the entry in the configured backends that the policy
       inquiry is regarding. It is pulled from the `BACKENDS` configuration value.

    * `auth` represents the authentication state of the request. An unauthenticated
      request has `auth = None`, whereas an authenticated request has `auth` as
      a dictionary with two keys: `auth_plugin` which points to the TurnpikeAuthPlugin
      instance that successfully authenticated the request, and `auth_data` which
      is a dictionary containing data about the authenticated principal. Its contents
      are specific to each TurnpikeAuthPlugin type.

    * `headers` is a dictionary of headers to include in the HTTP response returned
      to the client.

    * `status_code` is None, 200, 401, or 403. If it is None, then no decision has
      been made about whether the request is allowed or not. If we get to the end
      of the chain of plugins without a decision, the `DEFAULT_RESPONSE_CODE` from
      the configuration will be used. If a plugin sets the `status_code` to one of
      the integer values, then no further plugins in the chain will process the
      requests and it will be returned immediately to the client.

    * `data` is an arbitrary dictionary. If two plugins need to share data in a
      way that does not get returned to the client, putting that data in this
      dictionary is the proper way to go.
    """

    backend = None
    auth = None
    headers = {}
    status_code = None
    data = {}

    def __str__(self):
        return f"PolicyContext: backend={self.backend} auth={self.auth}, headers={self.headers}, status_code={self.status_code}"


class TurnpikePlugin:
    """
    TurnpikePlugin represents a component in the policy chain. By including a
    subclass of TurnpikePlugin in your configuration's `PLUGIN_CHAIN` list, it
    will have the opportunity to process incoming requests.

    Methods:

    * `process(self, context)` - All subclasses _must_ implement this method.
      The `context` argument is an instance of `PolicyContext`. The `process`
      method must also return a `PolicyContext` object. It will probably be
      useful in your `process` method to access Flask app and request context,
      using `Flask.current_app` or `Flask.request`.
    """

    def __init__(self, app):
        self.app = app

    def process(self, context):
        raise NotImplementedError()


class TurnpikeAuthPlugin:
    """
    TurnpikeAuthPlugin is used by the `turnpike.plugins.auth.AuthPlugin` to
    enable custom authentication schemes. by including a subclass of TurnpikeAuthPlugin
    in your configuration's `AUTH_PLUGIN_CHAIN` list, it will have the opportunity
    to authenticate and authorize incoming requests.

    Methods:

    * `process(self, context, backend_auth)` - All subclasses _must_ implement this method.
      Similar to `TurnpikePlugin`, this method is the core of the plugin, doing the
      authentication and authorization work. It returns a `PolicyContext` object.

      The `context` argument is a `PolicyContext` instance.

      The `backend_auth` argument is a dictionary of the authentication/authorization
      policy configured for this route. Each key is an authentication type, and the value
      is a string evaluatable as a Python expression. The plugin should look for
      supported authentication types, and if it establishes that the user is
      authenticated, it should evaluate the expression in the context of the
      authentication data to determine if the principal is authorized.

      Successfully authentication should result in the `auth` attribute of the returned
      `PolicyContext` to be set. Unsuccessful authorization should result in the
      `status_code` attribute of the returned `PolicyContext` to be set to 403.
    """

    name = "unnamed"
    principal_type = "unknown"

    def __init__(self, app):
        self.app = app

    def process(self, context, backend_auth):
        raise NotImplementedError()
