from typing import Optional

from turnpike.model.authentication import Authentication


class OIDCServiceAccountAuthentication(Authentication):
    """A class representing the OIDC authentication method for the back end."""

    class ServiceAccount:
        """A class representing an OIDC service account."""

        def __init__(self, client_id: str, scopes: list[str]):
            self.client_id: str = client_id
            self.scopes = scopes

    def __init__(self, backend_name: str, raw_oidc_definition: dict):
        service_accounts: Optional[list[dict]] = raw_oidc_definition.get("serviceAccounts")
        if not service_accounts:
            raise NotImplementedError(
                f'The backend "{backend_name}" has an "oidc" authentication method but the "serviceAccounts" key is either missing or is empty'
            )

        self.service_accounts: list[OIDCServiceAccountAuthentication.ServiceAccount] = []
        self.service_accounts_client_id: dict[str, OIDCServiceAccountAuthentication.ServiceAccount] = {}
        for sa in service_accounts:
            client_id: Optional[str] = sa.get("clientId")
            if not client_id:
                raise NotImplementedError(
                    f'The backend "{backend_name}" has a "service account" defined without a properly defined client ID'
                )

            scopes: list[str] = sa.get("scopes", [])
            if scopes:
                for scope in scopes:
                    if not scope:
                        raise NotImplementedError(
                            f'The backend "{backend_name}" has a "service account" defined with a list that has an empty scope'
                        )

            service_account = OIDCServiceAccountAuthentication.ServiceAccount(client_id, scopes)

            self.service_accounts.append(service_account)
            self.service_accounts_client_id[service_account.client_id] = service_account

    def service_account_by_client_id(self, client_id: str) -> Optional[ServiceAccount]:
        return self.service_accounts_client_id.get(client_id)
