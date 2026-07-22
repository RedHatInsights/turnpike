from http import HTTPStatus
from typing import Optional

from flask import session, redirect, make_response

from turnpike.views.saml.generic_saml_view import GenericSAMLView
from turnpike.views.saml.saml_context import SAMLContext
from turnpike.security_logging import log_security_event


class SLSView(GenericSAMLView):
    """View for the SAML logout endpoint."""

    def get(self):
        """Logs the user out by removing any traces of the session."""
        saml_context = SAMLContext(self.saml_settings_type)

        request_id = None
        if "LogoutRequestID" in session:
            request_id = session["LogoutRequestID"]

        saml_userdata = session.get("samlUserdata", {})
        principal = (
            saml_userdata.get("urn:oid:0.9.2342.19200300.100.1.1", ["unknown"])[0] if saml_userdata else "unknown"
        )

        # Trigger the logout which clears everything both from the utility and
        # the Flask application.
        url: Optional[str] = saml_context.saml_authentication.process_slo(
            request_id=request_id, delete_session_cb=session.clear
        )

        errors = saml_context.saml_authentication.get_errors()
        if not errors:
            log_security_event("SAML_LOGOUT", principal=principal)
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
