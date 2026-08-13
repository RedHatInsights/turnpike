from flask import current_app, session

from turnpike.safe_eval import safe_eval

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
            auth_data = {k: v if (len(v) > 1 or (k in multi_value_attrs)) else v[0] for k, v in auth_tuples}
            uid = auth_data.get("urn:oid:0.9.2342.19200300.100.1.1")
            if uid:
                auth_data["username"] = uid if isinstance(uid, str) else uid[0]
            context.auth = dict(
                auth_data=auth_data,
                auth_plugin=self,
            )

            predicate = backend_auth["saml"]
            authorized = safe_eval(predicate, dict(user=auth_dict), backend_name=context.backend.get("name"))
            if not authorized:
                context.status_code = 403

        return context
