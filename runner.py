import importlib.util
import inspect
import json
import os
import ast

from framework.configurator.configurator import Configurator
from framework.connection.connection_pool import CONNECTION_POOL
from framework.log.logger import log
from framework.report.html_report import HTMLReportGenerator
from framework.report.test_result import TestResult

DEFAULT_MESSAGE_FORMAT = "\n{:=^200}\n"


def load_module_from_file(filepath: str):
    """Load a Python file as a module dynamically"""
    module_name = os.path.splitext(os.path.basename(filepath))[0]
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader, f"Unable to load module from {filepath}"
    spec.loader.exec_module(module)
    return module


def _get_class_tags(cls) -> set[str]:
    """
    Get tags from a test class.
    Supports:
      - TAGS = {"smoke","regression"}
      - tags = ["smoke", "regression"]
      - MARKERS = "smoke,regression"
    """
    tags = set()

    for attr in ("TAGS", "tags", "MARKERS", "markers"):
        val = getattr(cls, attr, None)
        if not val:
            continue

        if isinstance(val, str):
            # allow "smoke, regression"
            parts = [p.strip() for p in val.split(",") if p.strip()]
            tags.update(parts)
        elif isinstance(val, (list, tuple, set)):
            tags.update([str(x).strip() for x in val if str(x).strip()])

    return tags


class _MarkerExprEvaluator(ast.NodeVisitor):
    """
    Safe evaluator for marker expressions like:
      smoke
      regression and not smoke
      smoke or regression
    Allowed nodes: Name, BoolOp (And/Or), UnaryOp (Not), Paren via nested AST, Constant True/False
    """
    def __init__(self, tags: set[str]):
        self.tags = tags

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_Name(self, node: ast.Name):
        # "smoke" => True if "smoke" in TAGS
        return node.id in self.tags

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        raise ValueError("Only True/False constants allowed in marker expressions.")

    def visit_UnaryOp(self, node: ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not self.visit(node.operand)
        raise ValueError("Only 'not' is allowed as unary operator in marker expressions.")

    def visit_BoolOp(self, node: ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(self.visit(v) for v in node.values)
        if isinstance(node.op, ast.Or):
            return any(self.visit(v) for v in node.values)
        raise ValueError("Only 'and'/'or' are allowed in marker expressions.")

    def generic_visit(self, node):
        raise ValueError(f"Unsupported syntax in marker expression: {type(node).__name__}")


def _marker_match(expr: str, tags: set[str]) -> bool:
    """
    Evaluate marker expression against a class's tags.
    Example expr: 'smoke and not regression'
    """
    if not expr:
        return True

    # Normalize common pytest-like whitespace
    expr = expr.strip()
    if not expr:
        return True

    try:
        tree = ast.parse(expr, mode="eval")
        evaluator = _MarkerExprEvaluator(tags)
        return bool(evaluator.visit(tree))
    except Exception as e:
        raise ValueError(f"Invalid -m/--markers expression '{expr}': {e}")


def run_class(cls, results, test_config):
    """Run all test methods in a class (your existing behavior)."""
    param_data = getattr(cls, "_parametrize_args", None)
    configurator = Configurator(test_config)
    instance = configurator.inject(cls, configurator.eyesight_config())

    if not param_data:
        try:
            instance.do_setup()
            log.info(DEFAULT_MESSAGE_FORMAT.format(f"Running test: {instance.__class__.__name__}"))
            instance.do_test()
            log.info(DEFAULT_MESSAGE_FORMAT.format(f"Test passed: {instance.__class__.__name__} Passed"))
            results.append(TestResult(cls.__name__, "passed"))
        except AssertionError as e:
            log.error(DEFAULT_MESSAGE_FORMAT.format(f"Test Failed: {instance.__class__.__name__} Failed"))
            results.append(TestResult(cls.__name__, "failed", str(e)))
        finally:
            instance.do_teardown()
    else:
        log.info(DEFAULT_MESSAGE_FORMAT.format(f"Running Parametrized test {cls.__name__}"))
        arg_names, arg_values_list = param_data
        for idx, values in enumerate(arg_values_list, 1):
            log.info(DEFAULT_MESSAGE_FORMAT.format(f"Running {cls.__name__}[{idx}] with {values}"))
            kwargs = dict(zip(arg_names, values))
            for k, v in kwargs.items():
                setattr(instance, k, v)
            try:
                instance.do_setup()
                log.info(DEFAULT_MESSAGE_FORMAT.format(f"Running test: {cls.__name__}[{idx}]"))
                instance.do_test()
                log.info(DEFAULT_MESSAGE_FORMAT.format(f"Test passed: {instance.__class__.__name__} Passed"))
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", "passed"))
            except AssertionError as e:
                log.error(DEFAULT_MESSAGE_FORMAT.format(f"Test Failed: {instance.__class__.__name__} Failed"))
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", "failed", str(e)))
            finally:
                instance.do_teardown()


def runner(
    test_suite: str,
    test_config: str = None,
    testbed_config=None,
    report_config=None,
    case: str = None,
    keyword: str = None,
    markers: str = None,
):
    """
    Enhanced runner supports:
      - file.py::ClassName (existing)
      - --case (substring match on class name)
      - -k/--keyword (substring match on class name)
      - -m/--markers marker expression evaluated against class tags
    """
    results = []

    # Existing support: file.py::ClassName
    single_test_class = False
    selected_class_name = None

    if "::" in test_suite:
        single_test_class = True
        suite_path, selected_class_name = test_suite.split("::", 1)
        module = load_module_from_file(suite_path)
    else:
        module = load_module_from_file(test_suite)

    discovered = []
    for name, cls in inspect.getmembers(module, inspect.isclass):
        if cls.__module__ != module.__name__:
            continue
        # Only run classes that look like your tests
        if not hasattr(cls, "do_test") or not callable(getattr(cls, "do_test")):
            continue
        discovered.append((name, cls))

    # Apply filters
    filtered = []
    for name, cls in discovered:
        # file.py::ClassName exact selection
        if single_test_class and name != selected_class_name:
            continue

        # --case substring filter
        if case and case not in name:
            continue

        # -k substring filter
        if keyword and keyword not in name:
            continue

        # -m markers expression filter
        if markers:
            tags = _get_class_tags(cls)
            if not _marker_match(markers, tags):
                continue

        filtered.append((name, cls))

    if not filtered:
        msg = [
            "No matching tests found after filtering.",
            f"  Suite: {test_suite}",
            f"  --case: {case}",
            f"  -k: {keyword}",
            f"  -m: {markers}",
            f"  Discovered classes: {[n for n, _ in discovered]}",
        ]
        raise RuntimeError("\n".join(msg))

    log.info(DEFAULT_MESSAGE_FORMAT.format("Selected tests"))
    for name, cls in filtered:
        tags = sorted(_get_class_tags(cls))
        tag_str = f" tags={tags}" if tags else ""
        log.info(f" - {name}{tag_str}")

    # Run
    for name, cls in filtered:
        log.info(f"\nRunning class: {name}")
        run_class(cls, results, test_config)

    # Cleanup + reporting (existing)
    if CONNECTION_POOL is not None:
        CONNECTION_POOL.close_all()

    HTMLReportGenerator(results, title="Radius Tests Report").generate("radius_report.html")
    json_results = [result.__dict__ for result in results]
    with open("radius_report.json", "w", encoding="utf-8") as json_file:
        json.dump(json_results, json_file, indent=4)


if __name__ == "__main__":
    runner("test/radius/radius_test.py")
