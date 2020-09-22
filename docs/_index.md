---
title: Turnpike Web Gateway
date: 2020-09-14T18:20:00-04:00
---

The Turnpike Web Gateway offers protected access to hosted web applications and API services using SAML authentication
and attribute-based access control. It uses the Nginx web server, a Python/Flask policy server, and a Redis database.

When to use Turnpike
--------------------

If you are developing an application or service on the Cloud Services Platform that has views or APIs that are not
meant for customer consumption, you probably want to expose them through Turnpike. Examples of use cases include:

* Administrative or monitoring interfaces to your cloud.redhat.com-hosted application or service
* Exposing platform-hosted data to trusted applications running behind the Red Hat firewall
* Enabling support interfaces to your application or service

If what you're building is meant to be accessed by customers or customer-managed infrastructure, the 3Scale API Gateway
is the proper place to go. If what you are building has components not meant for customer use or access, Turnpike is an
appropriate place to route through.

How it works
------------

Turnpike makes use of the [auth_request][auth_request] feature of Nginx, which delegates authentication/authorization
to a web service. The web service itself is a [Flask][flask] application that implements a SAML Service Provider and
allows/denies specific requests to routed web applications & APIs based on the attributes of the SAML assertion. Session
data is stored in Redis to better manage content and expiry.

![Turnpike Architecture](turnpike-architecture.png)

A successful SAML user request workflow looks like:

![Turnpike Userflow](turnpike-userflow.png)

A successful mTLS request workflow looks like:

![mTLS Flow](turnpike-mtls.png)

Route map and Attribute based access control
--------------------------------------------

Turnpike is configured using a route map that lists what URLs to expose, what upstream URLs to reverse proxy them to,
and what authentication/authorization requirements it should enforce. For example:

    - name: turnpike
      route: /api/turnpike
      origin: http://web:5000/api/turnpike
      auth:
        saml: "True"
    - name: healthcheck
      route: /_healthcheck
      origin: http://web:5000/_healthcheck

The map is a list of routes. Each route has three required fields: a `name` which must be a unique string, a `route`
which represents a URL prefix substring to match for this route, and an `origin` which represents the URL to proxy to.
The substring matching of `route` and the rewriting to `origin` are the same as the Nginx location matching and rewrite
rules.

If a route has a key `auth`, then it will require authentication. The `auth` key's value should be a set of key/value
pairs representing supported authentication schemes and corresponding authorization rules. At this time, the only
supported authentication schemes are `saml`, `x509`.

The value associated with `saml` should be a Python expression that evaluates to `True` or `False`. The only variable
in the expression is a dictionary `user` which contains the SAML assertion for the requesting user. If the assertion
had multiple `AttributeValue`s for a single `Attribute`, then those values are represented as a list of values.

> Note: The Red Hat SSO SAML assertion will return LDAP roles which Turnpike makes available to your predicates via:
`user['Role']`. Production uses your production LDAP groups, while Stage and other non-prod environments use groups
configured at: https://rover.stage.redhat.com/groups/

So for example, if you wanted to limit access to a route to users who had the role `admin`, `auditor`, or `manager`,
your Python expression could be:

    set(['admin', 'auditor', 'manager']).intersection(set(user['Role']))

The evaluation would use set-logic to look for overlaps. If there were any overlaps, the predicate would evaluate to
`True`. If not, `False`.

> Note: Presently the RHCSP Turnpike installation does terminate mTLS and thus does not report the necessary HTTP
  headers to enforce x.509 authn/authz requests. This is forthcoming.

`x509` also takes a Python expression which evaluates to `True` or `False`. It is passed a dictionary `x509` which
contains two attributes: `subject_dn` and `issuer_dn` which can be used to further restrict which certs can be used
(nginx already verifies the trust chain based on the configured CA file).

For example to restrict the endpoint to a certificate with the DN of `/CN=test`, you could use:

    x509['subject_dn'] == '/CN=test'

X-RH-Identity
-------------

Like services that are customer-facing, services routed by Turnpike present information about the authenticated
principal using the `X-RH-Identity` header, however whereas customer-facing services receive a header with a type of
`User` or `System`, Turnpike issued headers have a type of `Associate` for SAML authenticated users and of `X509` for
mTLS authenticated users.

These are best shared by example. For SAML authentication:

    {
      "identity": {
        // The associate section contains the Associate type principal data
        "associate": {
          // The Roles correspond to LDAP groups
          "Role": [
            "some-ldap-group",
            "another-ldap-group"
          ],
          "email": "jschmoe@redhat.com",
          "givenName": "Joseph",
          "rhatUUID": "01234567-89ab-cdef-0123-456789abcdef",
          "surname": "Schmoe"
        },
        // In the future, Associates might be authenticated through other means
        "auth_type": "saml-auth",
        // The Associate type asserts that the request comes from an active Red Hat employee
        "type": "Associate"
      }
    }

Or alternatively, for mTLS:

    {
      "identity": {
        "x509": {
          // The subject presented by the client
          "subject_dn": "/CN=some-host.example.com",
          // All trusted CAs will have to be configured by the platform team at the edge
          "issuer_dn": "/CN=certificate-authority.example.com"
        },
        "auth_type": "X509",
        // The X509 type asserts that the request comes from a system with a trusted x.509 certificate
        "type": "X509"
      }
    }

If your application needs to vary its functionality based on the requesting user or if your application needs to
perform more granular access control, it will need to consume this header to do so.

URL conventions in Turnpike
----------------------------------

When creating Turnpike routes, to promote harmonious co-existence, your Turnpike-exposed URLs should fit into the
following rules:

* If you're exposing an API for app `myapp`, your route should begin with `/api/myapp/`
* If you're exposing a web application with its own HTML interface for app `myapp`, your route should being with
  `/app/myapp/`

In the future, we imagine having a common chrome for building user interfaces integated with Turnpike routed APIs.

There are no restrictions on what your origin URLs must look like, however be sure in your exposed application or APIs
to be aware of URLs being returned to the user in HTML documents or API hypermedia, so that they conform to the URLs as
the user would perceive them.

If your origin route is to the root path of your service, your `route` and `origin` values _must_ contain a trailing
slash.

For security purposes, it's advisable to have a different service serving Turnpike routed views than the one serving
3scale routed views. If you choose that the service exposed via Turnpike be the same service you expose via 3scale, you
are _strongly_ encouraged to pick a completely different URL space in your service to differentiate Turnpike exposed
views from 3scale exposed views. For example, the RBAC service exposes its Turnpike routed views from the URL prefix
`/_private/` so as not to accidentally expose these views to the public.

How to create a new Turnpike Route
----------------------------------

The route map for Turnpike is managed in app-interface as a `ConfigMap`. To create or modify a route for the RHCSP
Turnpike installation, you'll have to modify it and create a Merge Request.

1. Start with stage. In the app-interface tree, edit the file at:
   `/resources/insights-stage/turnpike-stage/turnpike-stage-routes.configmap.yml`

2. Make sure you allow Turnpike access to your service's namespace. Modify your namespace file, which if your app's
   name is `myapp` should be at `/data/services/insights/myapp/namespaces/stage-myapp-stage.yml`. Under the
   `networkPoliciesAllow` key, add to the list `$ref: /services/insights/turnpike/namespaces/stage-turnpike-stage.yml`

3. Open a Merge Request. Please tag `@jginsber` or `@kwalsh` to double check your changes.

4. If the merge request works, you should be able to see your route in action at `internal.cloud.stage.redhat.com`

5. If everything looks good, we can move to production. In the app-interface tree, edit the files as before at
   `/resources/insights-prod/turnpike-prod/turnpike-prod-routes.configmap.yml` and
   `/data/services/insights/myapp/namespaces/prod-myapp-prod.yml` (but don't forget to allow the `prod-turnpike-prod`
   namespace instead of the `stage-turnpike-stage` one.)

6. Open a Merge Request. Please tag whomever double-checked your stage changes.

If the merge request works, you should be able to see your route in action at `internal.cloud.redhat.com`.

Reporting issues
----------------

If you have questions, reach out to the Platform Infrastructure team. To report issues, do so at the GitHub repository
for Turnpike: https://github.com/RedHatInsights/turnpike


[auth_request]: https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/
[flask]: https://flask.palletsprojects.com/en/1.1.x/
