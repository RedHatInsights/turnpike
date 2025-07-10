from flask import views, redirect, request

from turnpike.views.saml.saml_context import SAMLContext


class LoginView(views.MethodView):
    """View for the SAML's login process."""

    def get(self):
        """Redirect the user to the SSO by appending the request's next URL if any."""
        saml_context = SAMLContext()

        # The incoming request may contain the "next" query parameter which
        # contains the original URI the user sent the request to.
        #
        # This query parameter is set in the "login_url" method of the SAML
        # plugin.
        next_url = request.args.get("next", "/")

        # Redirect the user to the login URI and make sure that they
        # get redirected to the original URI they specified after the login
        # process has completed.
        return redirect(location=saml_context.saml_authentication.login(return_to=next_url))
