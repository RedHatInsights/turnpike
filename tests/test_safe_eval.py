import unittest

from turnpike.safe_eval import safe_eval


class TestSafeEvalAllowedPatterns(unittest.TestCase):

    def test_literal_true(self):
        self.assertTrue(safe_eval("True", {}))

    def test_literal_false(self):
        self.assertFalse(safe_eval("False", {}))

    def test_simple_comparison(self):
        result = safe_eval('registry["org_id"] == "999"', dict(registry={"org_id": "999"}))
        self.assertTrue(result)

    def test_simple_comparison_false(self):
        result = safe_eval('registry["org_id"] == "999"', dict(registry={"org_id": "123"}))
        self.assertFalse(result)

    def test_boolean_and(self):
        result = safe_eval(
            'x509["subject_dn"] == "/CN=test" and x509["issuer_dn"] == "/O=Red Hat"',
            dict(x509={"subject_dn": "/CN=test", "issuer_dn": "/O=Red Hat"}),
        )
        self.assertTrue(result)

    def test_boolean_or(self):
        result = safe_eval(
            'x509["subject_dn"] == "/CN=a" or x509["subject_dn"] == "/CN=b"',
            dict(x509={"subject_dn": "/CN=b"}),
        )
        self.assertTrue(result)

    def test_not_operator(self):
        result = safe_eval("not False", {})
        self.assertTrue(result)

    def test_set_intersection(self):
        result = safe_eval(
            'set(user["roles"]).intersection(set(["admin", "editor"]))',
            dict(user={"roles": ["admin", "viewer"]}),
        )
        self.assertTrue(result)

    def test_set_intersection_empty(self):
        result = safe_eval(
            'set(user["roles"]).intersection(set(["admin", "editor"]))',
            dict(user={"roles": ["viewer"]}),
        )
        self.assertFalse(result)

    def test_len_call(self):
        result = safe_eval('len(user["roles"]) > 0', dict(user={"roles": ["admin"]}))
        self.assertTrue(result)

    def test_any_true(self):
        result = safe_eval("any([False, True, False])", {})
        self.assertTrue(result)

    def test_any_false(self):
        result = safe_eval("any([False, False])", {})
        self.assertFalse(result)

    def test_any_empty(self):
        result = safe_eval("any([])", {})
        self.assertFalse(result)

    def test_all_true(self):
        result = safe_eval("all([True, True, True])", {})
        self.assertTrue(result)

    def test_all_false(self):
        result = safe_eval("all([True, False, True])", {})
        self.assertFalse(result)

    def test_all_empty(self):
        result = safe_eval("all([])", {})
        self.assertTrue(result)

    def test_in_operator(self):
        result = safe_eval('"admin" in user["roles"]', dict(user={"roles": ["admin", "viewer"]}))
        self.assertTrue(result)

    def test_string_with_special_chars(self):
        result = safe_eval(
            'x509["subject_dn"] == "/CN=test/O=Red Hat, Inc."',
            dict(x509={"subject_dn": "/CN=test/O=Red Hat, Inc."}),
        )
        self.assertTrue(result)

    def test_dict_get_method(self):
        result = safe_eval('user.get("role", "none") == "admin"', dict(user={"role": "admin"}))
        self.assertTrue(result)

    def test_string_startswith(self):
        result = safe_eval('x509["subject_dn"].startswith("/CN=")', dict(x509={"subject_dn": "/CN=test"}))
        self.assertTrue(result)

    def test_nested_subscript(self):
        result = safe_eval('user["data"]["org"] == "redhat"', dict(user={"data": {"org": "redhat"}}))
        self.assertTrue(result)

    def test_list_literal(self):
        result = safe_eval('"admin" in ["admin", "editor"]', {})
        self.assertTrue(result)

    def test_int_comparison(self):
        result = safe_eval('int(registry["org_id"]) > 100', dict(registry={"org_id": "200"}))
        self.assertTrue(result)

    def test_dict_literal_default(self):
        result = safe_eval('user.get("role", "none") == "none"', dict(user={}))
        self.assertTrue(result)

    def test_empty_dict_literal(self):
        result = safe_eval("len({}) == 0", {})
        self.assertTrue(result)

    def test_if_expression(self):
        result = safe_eval('True if user["role"] == "admin" else False', dict(user={"role": "admin"}))
        self.assertTrue(result)

    def test_any_generator_expression(self):
        result = safe_eval(
            "any(role in ['role-a', 'role-b'] for role in user['roles'])",
            dict(user={"roles": ["role-x", "role-b"]}),
        )
        self.assertTrue(result)

    def test_any_generator_expression_no_match(self):
        result = safe_eval(
            "any(role in ['role-a', 'role-b'] for role in user['roles'])",
            dict(user={"roles": ["role-x"]}),
        )
        self.assertFalse(result)

    def test_list_comprehension(self):
        result = safe_eval(
            'len([role for role in user["roles"] if role.startswith("foo")]) > 0',
            dict(user={"roles": ["foo-1"]}),
        )
        self.assertTrue(result)

    def test_all_generator_expression(self):
        result = safe_eval(
            'all(role in user["roles"] for role in ["role-a", "role-b"])',
            dict(user={"roles": ["role-a", "role-b", "role-c"]}),
        )
        self.assertTrue(result)

    def test_nested_comprehension(self):
        result = safe_eval("any(x + y > 5 for x in [1, 2] for y in [3, 4])", {})
        self.assertTrue(result)

    def test_comprehension_with_tuple_unpacking(self):
        result = safe_eval("all(a + b == 3 for (a, b) in [(1, 2), (2, 1)])", {})
        self.assertTrue(result)


class TestSafeEvalRejectedPatterns(unittest.TestCase):

    def test_import_rejected(self):
        result = safe_eval('__import__("os").system("echo pwned")', {})
        self.assertFalse(result)

    def test_dunder_class_rejected(self):
        result = safe_eval("().__class__.__bases__[0].__subclasses__()", {})
        self.assertFalse(result)

    def test_dunder_attribute_rejected(self):
        result = safe_eval("x509.__class__", dict(x509={}))
        self.assertFalse(result)

    def test_exec_rejected(self):
        result = safe_eval('exec("import os")', {})
        self.assertFalse(result)

    def test_eval_in_predicate_rejected(self):
        result = safe_eval('eval("True")', {})
        self.assertFalse(result)

    def test_open_rejected(self):
        result = safe_eval('open("/etc/passwd")', {})
        self.assertFalse(result)

    def test_lambda_rejected(self):
        result = safe_eval("(lambda: True)()", {})
        self.assertFalse(result)

    def test_syntax_error_returns_false(self):
        result = safe_eval("this is not valid python !!!", {})
        self.assertFalse(result)

    def test_unknown_variable_rejected(self):
        result = safe_eval('os.system("echo pwned")', {})
        self.assertFalse(result)

    def test_getattr_rejected(self):
        result = safe_eval('getattr(x509, "subject_dn")', dict(x509={}))
        self.assertFalse(result)

    def test_type_call_rejected(self):
        result = safe_eval("type(x509)", dict(x509={}))
        self.assertFalse(result)

    def test_pow_operator_rejected(self):
        result = safe_eval("2 ** 100", {})
        self.assertFalse(result)

    def test_comprehension_with_undefined_variable_rejected(self):
        result = safe_eval("any(x == y for x in [1, 2, 3])", {})
        self.assertFalse(result)

    def test_async_comprehension_rejected(self):
        result = safe_eval("[x async for x in y]", dict(y=[1, 2, 3]))
        self.assertFalse(result)

    def test_walrus_operator_rejected(self):
        result = safe_eval("(x := True)", {})
        self.assertFalse(result)

    def test_sandbox_escape_via_subclasses(self):
        result = safe_eval(
            "().__class__.__bases__[0].__subclasses__()",
            {},
        )
        self.assertFalse(result)

    def test_builtins_access_rejected(self):
        result = safe_eval("__builtins__", {})
        self.assertFalse(result)


class TestSafeEvalRuntimeErrors(unittest.TestCase):
    """Verify that runtime errors during eval() fail closed (return False)."""

    def test_keyerror_returns_false(self):
        result = safe_eval('registry["nonexistent"]', dict(registry={}))
        self.assertFalse(result)

    def test_attributeerror_returns_false(self):
        result = safe_eval('x509["dn"].startswith("/CN=")', dict(x509={"dn": None}))
        self.assertFalse(result)

    def test_typeerror_returns_false(self):
        result = safe_eval('len(registry["count"]) > 0', dict(registry={"count": 42}))
        self.assertFalse(result)

    def test_zero_division_returns_false(self):
        result = safe_eval("1 / 0 > 0", {})
        self.assertFalse(result)

    def test_non_string_expression_returns_false(self):
        result = safe_eval(123, {})
        self.assertFalse(result)

    def test_null_byte_expression_returns_false(self):
        result = safe_eval("True\x00", {})
        self.assertFalse(result)


class TestSafeEvalEdgeCases(unittest.TestCase):
    """Edge cases: None values, empty collections, missing keys, deep nesting."""

    def test_none_variable_value(self):
        result = safe_eval("x is None", {"x": None})
        self.assertTrue(result)

    def test_empty_string_comparison(self):
        result = safe_eval('user["name"] == ""', dict(user={"name": ""}))
        self.assertTrue(result)

    def test_empty_list_variable(self):
        result = safe_eval('len(user["roles"]) > 0', dict(user={"roles": []}))
        self.assertFalse(result)

    def test_missing_dict_key_returns_false(self):
        result = safe_eval('user["missing_key"] == "value"', dict(user={}))
        self.assertFalse(result)

    def test_deeply_nested_boolean(self):
        result = safe_eval(
            'x == "a" and (y == "b" or (z == "c" and w == "d"))',
            {"x": "a", "y": "b", "z": "c", "w": "d"},
        )
        self.assertTrue(result)

    def test_backend_name_in_logs(self):
        result = safe_eval('registry["bad_key"]', dict(registry={}), backend_name="my-service")
        self.assertFalse(result)


class TestSafeEvalBackwardCompatibility(unittest.TestCase):
    """Tests using predicate patterns found in actual backend configs."""

    def test_saml_true_predicate(self):
        self.assertTrue(safe_eval("True", dict(user={"name": ["alice"]})))

    def test_x509_true_predicate(self):
        self.assertTrue(safe_eval("True", dict(x509={"subject_dn": "/CN=test"})))

    def test_registry_true_predicate(self):
        self.assertTrue(safe_eval("True", dict(registry={"org_id": "123"})))

    def test_registry_org_id_check(self):
        result = safe_eval(
            'registry["org_id"] == "999"',
            dict(registry={"org_id": "999", "username": "alice"}),
        )
        self.assertTrue(result)

    def test_x509_dn_with_commas_and_slashes(self):
        result = safe_eval(
            'x509["subject_dn"] == "/CN=service/OU=Engineering/O=Red Hat, Inc./C=US"',
            dict(x509={"subject_dn": "/CN=service/OU=Engineering/O=Red Hat, Inc./C=US"}),
        )
        self.assertTrue(result)
