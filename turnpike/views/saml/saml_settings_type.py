from enum import Enum


class SAMLSettingsType(Enum):
    """Defines the type of SAML settings a view can use."""

    INTERNAL = "internal"
    PRIVATE = "private"
