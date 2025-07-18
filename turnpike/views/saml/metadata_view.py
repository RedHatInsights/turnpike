from http import HTTPStatus

from flask import make_response

from turnpike.views.saml.generic_saml_view import GenericSAMLView
from turnpike.views.saml.saml_context import SAMLContext


class MetadataView(GenericSAMLView):
    """View for serving SAML's metadata."""

    def get(self):
        """Return the SAML's metadata."""
        saml_context = SAMLContext(self.saml_settings_type)

        # Get the settings from the OneLogin utility.
        settings = saml_context.saml_authentication.get_settings()
        metadata = settings.get_sp_metadata()

        errors: list = settings.validate_metadata(metadata)
        if not errors:
            resp = make_response(metadata, HTTPStatus.OK)
            resp.headers["Content-Type"] = "text/xml"
        else:
            resp = make_response(", ".join(errors), HTTPStatus.INTERNAL_SERVER_ERROR)

        return resp
