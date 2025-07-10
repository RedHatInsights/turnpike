from flask import current_app, request, session, url_for

from ..plugin import TurnpikeAuthPlugin
from flask import current_app, request, session, url_for

from ..plugin import TurnpikeAuthPlugin


class SAMLAuthPlugin(TurnpikeAuthPlugin):
    name = "saml-auth"
    principal_type = "Associate"

    def process(self, context, backend_auth):
        """Authenticates the user by verifying their SAML attributes.

        After the user has completed the SAML login flow, which leaves the
        user data in Flask's session, we evaluate the back end's predicate
        against that data to check whether the user has access or not.
        """
        current_app.logger.debug("Begin SAML Auth plugin processing")
        if "saml" in backend_auth and "samlUserdata" in session:
            auth_dict = session["samlUserdata"]

            auth_tuples = auth_dict.items()
            if current_app.config["AUTH_DEBUG"]:
                current_app.logger.info(f"SAML auth_data: {auth_tuples}")

            multi_value_attrs = self.app.config["MULTI_VALUE_SAML_ATTRS"]
            context.auth = dict(
                auth_data={k: v if (len(v) > 1 or (k in multi_value_attrs)) else v[0] for k, v in auth_tuples},
                auth_plugin=self,
            )

            predicate = backend_auth["saml"]
            authorized = eval(predicate, dict(user=auth_dict))
            if not authorized:
                context.status_code = 403

        return context
