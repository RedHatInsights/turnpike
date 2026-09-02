import ast
import logging

logger = logging.getLogger(__name__)

_ALLOWED_NAMES = frozenset({"set", "len", "str", "int", "any", "all"})

_ALLOWED_BUILTINS = {"set": set, "len": len, "str": str, "int": int, "any": any, "all": all}

_ALLOWED_BINOPS = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.BitOr,
    ast.BitAnd,
    ast.BitXor,
)

_SAFE_METHODS = frozenset(
    {
        "intersection",
        "union",
        "difference",
        "issubset",
        "issuperset",
        "isdisjoint",
        "lower",
        "upper",
        "strip",
        "startswith",
        "endswith",
        "get",
        "keys",
        "values",
        "items",
    }
)


class _UnsafeExpression(Exception):
    pass


def _validate_node(node, variable_names):
    match node:
        case ast.Expression():
            _validate_node(node.body, variable_names)

        case ast.Constant():
            pass

        case ast.Name():
            if node.id not in _ALLOWED_NAMES and node.id not in variable_names:
                raise _UnsafeExpression(f"disallowed name: {node.id}")

        case ast.BoolOp():
            for value in node.values:
                _validate_node(value, variable_names)

        case ast.BinOp():
            if not isinstance(node.op, _ALLOWED_BINOPS):
                raise _UnsafeExpression(f"disallowed operator: {type(node.op).__name__}")
            _validate_node(node.left, variable_names)
            _validate_node(node.right, variable_names)

        case ast.UnaryOp():
            _validate_node(node.operand, variable_names)

        case ast.Compare():
            _validate_node(node.left, variable_names)
            for comparator in node.comparators:
                _validate_node(comparator, variable_names)

        case ast.Subscript():
            _validate_node(node.value, variable_names)
            _validate_node(node.slice, variable_names)

        case ast.List() | ast.Tuple() | ast.Set():
            for elt in node.elts:
                _validate_node(elt, variable_names)

        case ast.Dict():
            for key in node.keys:
                if key is not None:
                    _validate_node(key, variable_names)
            for val in node.values:
                _validate_node(val, variable_names)

        case ast.Call():
            if isinstance(node.func, ast.Name):
                if node.func.id not in _ALLOWED_NAMES:
                    raise _UnsafeExpression(f"disallowed function: {node.func.id}")
            elif isinstance(node.func, ast.Attribute):
                _validate_attribute(node.func, variable_names)
            else:
                raise _UnsafeExpression(f"disallowed call type: {type(node.func).__name__}")
            for arg in node.args:
                _validate_node(arg, variable_names)
            for kw in node.keywords:
                _validate_node(kw.value, variable_names)

        case ast.Attribute():
            _validate_attribute(node, variable_names)

        case ast.IfExp():
            _validate_node(node.test, variable_names)
            _validate_node(node.body, variable_names)
            _validate_node(node.orelse, variable_names)

        case ast.GeneratorExp() | ast.ListComp() | ast.SetComp():
            comp_variable_names = _validate_comprehension_generators(node.generators, variable_names)
            _validate_node(node.elt, comp_variable_names)

        case ast.DictComp():
            comp_variable_names = _validate_comprehension_generators(node.generators, variable_names)
            _validate_node(node.key, comp_variable_names)
            _validate_node(node.value, comp_variable_names)

        case _:
            raise _UnsafeExpression(f"disallowed node type: {type(node).__name__}")


def _validate_comprehension_generators(generators, variable_names):
    for generator in generators:
        if generator.is_async:
            raise _UnsafeExpression("disallowed async comprehension")

        _validate_node(generator.iter, variable_names)
        variable_names = variable_names | _extract_target_names(generator.target)

        for if_clause in generator.ifs:
            _validate_node(if_clause, variable_names)

    return variable_names


def _extract_target_names(target):
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names = set()
        for elt in target.elts:
            names |= _extract_target_names(elt)
        return names

    raise _UnsafeExpression(f"disallowed comprehension target: {type(target).__name__}")


def _validate_attribute(node, variable_names):
    if node.attr.startswith("_"):
        raise _UnsafeExpression(f"disallowed attribute: {node.attr}")
    if node.attr not in _SAFE_METHODS:
        raise _UnsafeExpression(f"disallowed method: {node.attr}")
    _validate_node(node.value, variable_names)


def safe_eval(expression, variables, backend_name=None):
    label = f"backend {backend_name}" if backend_name else "unknown backend"

    if expression == "True":
        return True
    if expression == "False":
        return False

    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, TypeError, ValueError):
        logger.error("Predicate is not valid Python for %s: %s", label, expression)
        return False

    try:
        _validate_node(tree, frozenset(variables.keys()))
    except _UnsafeExpression as exc:
        logger.error("Predicate rejected for %s (%s): %s", label, exc, expression)
        return False

    eval_globals = {"__builtins__": {}}
    eval_globals.update(_ALLOWED_BUILTINS)
    eval_globals.update(variables)
    try:
        return eval(compile(tree, "<predicate>", "eval"), eval_globals)
    except Exception:
        logger.error("Predicate evaluation failed for %s: %s", label, expression, exc_info=True)
        return False
