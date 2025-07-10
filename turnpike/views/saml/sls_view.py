from http import HTTPStatus

from black.brackets import Optional
from flask import views, session, redirect, make_response

from turnpike.views.saml.saml_context import SAMLContext


class SLSView(views.MethodView):
    """View for the SAML logout endpoint."""

    def get(self):
        """Logs the user out by removing any traces of the session."""
        saml_context = SAMLContext()

        request_id = None
        if "LogoutRequestID" in session:
            request_id = session["LogoutRequestID"]

        # Trigger the logout which clears everything both from the utility and
        # the Flask application.
        url: Optional[str] = saml_context.saml_authentication.process_slo(request_id=request_id, delete_session_cb=session.clear)

        errors = saml_context.saml_authentication.get_errors()
        if not errors:
            if url is not None:
                return redirect(url)
            else:
                return redirect("/")
        else:
            if saml_context.saml_authentication.get_settings().is_debug_active():
                error_reason = saml_context.saml_authentication.get_last_error_reason()
            else:
                error_reason = ""
            resp = make_response(error_reason, HTTPStatus.INTERNAL_SERVER_ERROR)
            resp.headers["Content-Type"] = "text/plain"
            return resp
