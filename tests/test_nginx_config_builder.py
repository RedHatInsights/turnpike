import os
import sys
import unittest
from unittest import mock

import jinja2

sys.path.append(os.path.abspath("./nginx"))

from configuration_builder.build_config import write_nginx_locations

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "../nginx/configuration_builder/templates/nginx_location_template.conf.j2",
)


class TestNginxLocationTemplateRendering(unittest.TestCase):
    """Tests that the nginx location template renders error_page 401 conditionally based on SAML auth."""

    def setUp(self):
        with open(TEMPLATE_PATH) as f:
            self.template = jinja2.Template(f.read())

    def _render(self, **backend):
        defaults = {
            "name": "test-backend",
            "route": "/api/test/",
            "origin": "http://test.svc.cluster.local:8080/api/test/",
            "timeout": 60,
            "buffering": "on",
            "headers": [],
        }
        defaults.update(backend)
        return self.template.render(**defaults)

    def test_saml_backend_has_error_page_401(self):
        """Backends with SAML auth should redirect 401s to the SAML login page."""
        output = self._render(auth={"saml": "True", "x509": "True"})
        self.assertIn("error_page 401 = @error401", output)

    def test_registry_backend_no_error_page_401(self):
        """Backends with only registry auth should not redirect 401s."""
        output = self._render(auth={"registry": "True"})
        self.assertNotIn("error_page 401", output)

    def test_oidc_backend_no_error_page_401(self):
        """Backends with only OIDC auth should not redirect 401s."""
        output = self._render(auth={"oidc": {"serviceAccounts": []}})
        self.assertNotIn("error_page 401", output)

    def test_x509_only_backend_no_error_page_401(self):
        """Backends with only x509 auth should not redirect 401s."""
        output = self._render(auth={"x509": "True"})
        self.assertNotIn("error_page 401", output)

    def test_no_auth_backend_no_error_page_401(self):
        """Backends without any auth should not redirect 401s."""
        output = self._render()
        self.assertNotIn("error_page 401", output)


class TestNginxConfigBuilder(unittest.TestCase):
    test_backends = [
        {
            "name": "backend-1",
            "origin": "http://service-one-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/service-one",
            "auth": {"saml": True},
        },
        {
            "name": "backend-2",
            "origin": "http://test-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/test",
            "auth": {"saml": True},
        },
        {
            "name": "backend-3",
            "origin": "http://test-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/test/v1/service",
            "auth": {"saml": True},
        },
        {
            "name": "backend-4",
            "origin": "http://service-three-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/service-three",
            "auth": {"saml": True},
        },
        {
            "name": "backend-5",
            "origin": "http://test-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/test/v1/service/more/specific",
            "auth": {"saml": True},
        },
        {
            "name": "backend-6",
            "origin": "http://test-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/test/v1/service/less",
            "auth": {"saml": True},
        },
        {
            "name": "backend-7",
            "origin": "http://service-one-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/service-one/v1",
            "auth": {"saml": True},
        },
        {
            "name": "backend-8",
            "origin": "http://service-four-svc.test-namespace.svc.cluster.local:8080",
            "route": "/api/service-four",
            "auth": {"saml": True},
        },
    ]

    def test_nginx_locations_written(self):
        """Tests that all the Nginx locations are opened to be written."""
        get_resolver_mock = mock.Mock()
        open_mock = mock.mock_open()

        # Call the function under test.
        with (
            mock.patch("configuration_builder.build_config.open", open_mock, create=True),
            mock.patch("configuration_builder.build_config.get_resolver", get_resolver_mock),
        ):
            write_nginx_locations(self.test_backends, {})

        # Assert that the files were "open to be written" in the particular order that we expect.
        call_list = open_mock.call_args_list

        self.assertEqual(
            9,
            len(call_list),
            'the "open" function to write to a file should have been called nine times, one for loading the template, and eight more for the specific Nginx locations',
        )

        self.assertEqual(
            "/etc/nginx/configuration_builder/templates/nginx_location_template.conf.j2",
            call_list[0].args[0],
        )

        for i in range(1, 8):
            self.assertEqual((f"/etc/nginx/api_conf.d/backend-{i}.conf", "w"), call_list[i].args)
