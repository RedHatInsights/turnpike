Turnpike Web Gateway
====================

The Turnpike Web Gateway offers protected access to hosted web applications and API services using SAML authentication
and attribute-based access control. It uses the Nginx web server, a Python/Flask policy server, and a Redis database.

How it works
------------

Turnpike makes use of the [auth_request][auth_request] feature of Nginx, which delegates authentication/authorization
to a web service. The web service itself is a [Flask][flask] application that implements a SAML Service Provider and
allows/denies specific requests to routed web applications & APIs based on the attributes of the SAML assertion. Session
data is stored in Redis to better manage content and expiry.

![Turnpike Architecture](turnpike-architecture.png)

A successful service request workflow looks like:

![Turnpike Userflow](turnpike-userflow.png)

SAML Service Provider Configuration
-----------------------------------

The implementation of a SAML service provider uses the OneLogin [python3-saml][python3-saml] library.

As with any SAML SP configuration, you will need:

1. An SSL certificate and key for your Turnpike gateway
2. The SSL certificate for your SAML Identity Provider (IdP)
3. The configuration of your Identity Provider as exposed by their IdP metadata endpoint.

Then in your copy of the Turnpike code, in `/saml` create the following files:

1. `settings.json`- The metadata settings for the IdP and SP (an [example][settings-example])
2. `advanced_settings.json` - Advanced SAML settings for the IdP and SP (an [example][adv-settings-example])

You can fill out the latter two by finding corresponding fields in your IdP's metadata file and with collaboration with
their staff. For the Service Provider urls, you should use the following paths relative to your Turnpike hostname:

* Entity ID/metadata URL: `/saml/metadata.xml`
* ACS: `/saml/acs/`
* SLS: `/saml/sls/`

If you're looking to simply demo Turnpike or aren't ready to integrate with your real IdP yet, you can use the free
SAML test integration services available at https://samltest.id

You will also need to generate a TLS certificate for the hostname you're going to use to access your running development
environment. In `/nginx/certs`, name the certificate as `cert.pem` and the private key as `key.pem`.

If you are deploying Turnpike in Kubernetes or OpenShift, you should mount these configuration files using a
combination of ConfigMap and Secret resources mounted into your running pods.

Running Using Docker Compose
----------------------------

The simplest way to run Turnpike locally is using Docker Compose.

First, you need to set proper environment variables. Copy the `.env.example` file to `.env`, copy the
`dev-config.py.example` to `dev-config.py`,  and customize them both as needed. You'll
need to generate a secret key for session security and you'll need to set the `SERVER_NAME` to the hostname you're
using for your SAML Service Provider, the same as the subject in your SP certificate.

Then, from the root of your copy of Turnpike, simply run:

    docker-compose build
    docker-compose up

If the subject of the SP certificate does not resolve to your local machine, you may have to add a mapping in your
`/etc/hosts` file. For example, if you issued your SP certificate to `cn=turnpike.example.com`, then you may need to add
to your `/etc/hosts` file a line:

    127.0.0.1  turnpike.example.com

Then, go to https://turnpike.example.com/api/turnpike/identity in your browser. You should immediately be redirected to
your configured IdP's login page, or if you're already logged into your IdP, a page that outputs the content of your
IdP's SAML assertion.

Route Map and Attribute Based Access Control
--------------------------------------------

Whether in Docker Compose or in Kubernetes/OpenShift, Turnpike expects that in the Flask container it will be able to
find its route map and access control list at `/etc/turnpike/backends.yml`. For Docker Compose, the file in your copy
of Turnpike `dev-backends.yml` is mounted into the Flask container at this path:

    - name: turnpike
      route: /api/turnpike
      origin: http://web:5000/api/turnpike
      auth:
        saml: "True"
    - name: healthcheck
      route: /_healthcheck
      origin: http://web:5000/_healthcheck

The file is a list of routes. Each route has three required fields: a `name` which must be a unique string, a `route`
which represents a URL prefix substring to match for this route, and an `origin` which represents the URL to proxy to.
The substring matching of `route` and the rewriting to `origin` are the same as the Nginx location matching and rewrite
rules.

If a route has a key `auth`, then it will require authentication. The `auth` key's value should be a set of key/value
pairs representing supported authentication schemes and corresponding authorization rules. At this time, the only
supported authentication scheme is `saml`. The value associated with `saml` should be a Python expression that evaluates
to `True` or `False`. The only variable in the expression is a dictionary `user` which contains the SAML assertion for
the requesting user. If the assertion had multiple `AttributeValue`s for a single `Attribute`, then those values are
represented as a list of values.

So for example, if you wanted to limit access to a route to users who had the role `admin`, `auditor`, or `manager`,
your Python expression could be:

    set(['admin', 'auditor', 'manager']).intersection(set(user['roles']))

The evaluation would use set-logic to look for overlaps. If there were any overlaps, the predicate would evaluate to
`True`. If not, `False`.

Customizing and Extending Turnpike
----------------------------------

Turnpike's policy service is based on passing a request through a series of plugins that
evaluate the request for conformity with the deployment policies. These plugins allows
for a great deal of customization and enhancement with minimal code changes.

The plugin chain is configurable in the Flask application using the `PLUGIN_CHAIN`
setting, which contains a list of Python references to classes that subclass the
`TurnpikePlugin` abstract base class.

The `turnpike.plugins.auth.AuthPlugin` has its own special type of sub-plugin that
implements the `TurnpikeAuthPlugin` abstract base class. By setting a separate list of
authentication methods as `AUTH_PLUGIN_CHAIN`, you can customize the way that your
deployment supports authenticating and authorizing requests.

See the docstrings on those classes for more details.

[auth_request]: https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/
[flask]: https://flask.palletsprojects.com/en/1.1.x/
[python3-saml]: https://github.com/onelogin/python3-saml
[settings-example]: https://github.com/onelogin/python3-saml/blob/master/demo-flask/saml/settings.json
[adv-settings-example]: https://github.com/onelogin/python3-saml/blob/master/demo-flask/saml/advanced_settings.json
