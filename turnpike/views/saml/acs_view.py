from http import HTTPStatus

from flask import views, session, request, redirect, current_app, make_response
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from turnpike.views.saml.saml_context import SAMLContext


class ACSView(views.MethodView):
    """A view that implements the Assertion Consumer Service endpoint."""

    def post(self):
        """Receive the SAML user data from SSO, store it in a session and redirect the user."""
        saml_context = SAMLContext()

        request_id = None
        if "AuthNRequestID" in session:
            request_id = session["AuthNRequestID"]

        saml_context.saml_authentication.process_response(request_id=request_id)

        errors: list = saml_context.saml_authentication.get_errors()
        if not errors:
            if "AuthNRequestID" in session:
                del session["AuthNRequestID"]

            # Store the user's data in Flask's session.
            session["samlUserdata"] = saml_context.saml_authentication.get_attributes()
            session["samlSessionIndex"] = saml_context.saml_authentication.get_session_index()

            # Obtain this view's URI, and make sure that the relay state, or
            # the original URL the user specified, are different, in order to
            # avoid any infinite redirection loops.
            self_url = OneLogin_Saml2_Utils.get_self_url(saml_context.request_data)
            if "RelayState" in request.form and self_url != request.form["RelayState"]:
                relay_state = saml_context.saml_authentication.redirect_to(request.form["RelayState"])
                current_app.logger.debug(f"Redirecting to {relay_state}")
                return redirect(location=relay_state)
            else:
                current_app.logger.debug("Redirecting to index")
                return redirect("/")
        else:
            if saml_context.saml_authentication.get_settings().is_debug_active():
                error_reason = saml_context.saml_authentication.get_last_error_reason()
            else:
                error_reason = ""
            resp = make_response(error_reason, HTTPStatus.INTERNAL_SERVER_ERROR)
            resp.headers["Content-Type"] = "text/plain"
            return resp
