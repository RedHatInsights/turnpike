from flask import views

from turnpike.views.saml.saml_settings_type import SAMLSettingsType


class GenericSAMLView(views.MethodView):
    """Defines a generic view to avoid repeating the initialization function on every SAML view."""

    def __init__(self, saml_settings_type: SAMLSettingsType = SAMLSettingsType.INTERNAL):
        """Initializes the SAML view.

        :param saml_settings_type: The type of settings the view will have to work with.
        """
        self.saml_settings_type = saml_settings_type
