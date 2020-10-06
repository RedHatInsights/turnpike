import os
import sys

sys.path.append(os.path.abspath("./nginx"))
import build_config


def test_happy_path():
    for backend in [
        dict(
            name="test1",
            route="/api/test",
            origin="http://test-svc.test-namespace.svc.cluster.local:8080/api",
            auth=dict(saml="True"),
        ),
        dict(name="test2", route="/public/test", origin="http://public-svc.test-namespace.svc.cluster.local/pub"),
        dict(
            name="test3",
            route="/_test/",
            origin="http://underscore-svc.test-namespace.svc.cluster.local:8000/",
            auth=dict(saml="True"),
        ),
    ]:
        assert build_config.validate_route(backend)


def test_invalid_path():
    for backend in [
        dict(
            name="test4",
            route="no-starting-slash",
            origin="http://test-svc.test-namespace.svc.cluster.local/foo",
            auth=dict(saml="True"),
        ),
        dict(
            name="test5",
            route="/api/test?_=1",
            origin="http://test-svc.test-namespace.svc.cluster.local/bar",
            auth=dict(saml="True"),
        ),
    ]:
        assert not build_config.validate_route(backend)


def test_untrusted_domain():
    assert not build_config.validate_route(
        dict(name="test6", route="/api/test", origin="https://bitcoin-miner.lulz/api/test", auth=dict(saml=True))
    )


def test_disallowed_urlspace():
    assert not build_config.validate_route(
        dict(
            name="test7",
            route="/highly/suspect",
            origin="http://test-svc.test-namespace.svc.cluster.local:8080/test",
            auth=dict(saml="True"),
        )
    )


def test_auth_required():
    assert not build_config.validate_route(
        dict(name="test8", route="/api/secure", origin="http://test-svc.test-namespace.svc.cluster.local:8000/api")
    )
