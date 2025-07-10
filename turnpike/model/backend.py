from typing import Optional

from turnpike.model.oidc_authentication import OIDCServiceAccountAuthentication
from turnpike.model.saml_authentication import SAMLAuthentication
from turnpike.model.x509_authentication import X509Authentication


class Backend:
    """A class representing a back end defined in the YAML file."""

    def __init__(self, raw_backend_definition: dict):
        # Parse the basic required elements from the back end.
        self.name: str = raw_backend_definition["name"]
        self.route: str = raw_backend_definition["route"]
        self.origin: str = raw_backend_definition["origin"]

        # Parse whether the back end only works within the VPN or not.
        self.private: Optional[bool] = raw_backend_definition.get("private")

        # Parse the back end's source IP authorization.
        self.source_ip: Optional[list[str]] = raw_backend_definition.get("source_ip")

        # Parse the back end's authentications.
        self.authentication_oidc: Optional[OIDCServiceAccountAuthentication] = None
        self.authentication_saml: Optional[SAMLAuthentication] = None
        self.authentication_x509: Optional[X509Authentication] = None

        auth = raw_backend_definition.get("auth")
        if auth:
            oidc_auth = auth.get("oidc")
            if oidc_auth:
                self.authentication_oidc = OIDCServiceAccountAuthentication(
                    backend_name=self.name, raw_oidc_definition=oidc_auth
                )

            saml_auth: Optional[str] = auth.get("saml")
            if saml_auth:
                self.authentication_saml = SAMLAuthentication(saml_auth)

            x509_auth: Optional[str] = auth.get("x509")
            if x509_auth:
                self.authentication_x509 = X509Authentication(x509_auth)

    def requires_authentication(self) -> bool:
        """Return "True" when the back end requires any kind of authentication."""
        return (
            (self.authentication_oidc is not None)
            or (self.authentication_saml is not None)
            or (self.authentication_x509 is not None)
        )
