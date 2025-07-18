from http import HTTPStatus

from flask import views, current_app, abort, request, make_response, session


class MockSAMLAssertionView(views.MethodView):
    """View for mocking the SAML ACS endpoint."""

    def post(self):
        """Stores the request's body in Flask's session."""
        if not current_app.config.get("TESTING"):
            abort(HTTPStatus.NOT_FOUND)
        if request.mimetype != "application/json":
            return make_response("Content type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)

        saml_user_data = request.json

        session["samlUserdata"] = saml_user_data
        session["samlSessionIndex"] = -1

        return make_response("", HTTPStatus.NO_CONTENT)
