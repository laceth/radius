import importlib.util
import inspect
import json
import logging as log
import os
import time

from framework.configurator.configurator import Configurator
from framework.connection.connection_pool import CONNECTION_POOL
from framework.log.logger import log
from framework.report.html_report import HTMLReportGenerator
from framework.report.test_result import TestResult


def load_module_from_file(filepath):
    """Load a Python file as a module dynamically"""
    module_name = os.path.splitext(os.path.basename(filepath))[0]
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_class(cls, results, test_config):
    """Run all test methods in a class"""
    param_data = getattr(cls, "_parametrize_args", None)
# dummy impl to enabling radius testcases run, need to be replaced with actual DI implementation
    configurator = Configurator(test_config)
    instance = configurator.inject(cls, configurator.eyesight_config())
    if not param_data:
        try:
            instance.do_setup()
            log.info("========================================Running test: %s ========================================" % cls.__name__)
            instance.do_test()
            log.info("\n========================================Test passed========================================%s Passed" % instance.__class__.__name__)
            results.append(TestResult(cls.__name__, 'passed'))
        except AssertionError as e:
            log.error("\n========================================Test Failed========================================\n %s Failed" % instance.__class__.__name__)
            results.append(TestResult(cls.__name__, 'failed', str(e)))
        finally:
            instance.do_teardown()
    else:
        arg_names, arg_values_list = param_data
        for idx, values in enumerate(arg_values_list, 1):
            log.info(f"========================================Running {cls.__name__}[{idx}] with {values} ========================================\n")
            kwargs = dict(zip(arg_names, values))
            for k, v in kwargs.items():
                setattr(instance, k, v)
            try:
                instance.do_setup()
                log.info(f"\n\n========================================Running test: {cls.__name__}[{idx}] ========================================\n\n")
                instance.do_test()
                log.info("\n========================================Test passed======================================== %s Passed" % instance.__class__.__name__)
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", 'passed'))
            except AssertionError as e:
                log.error(
                    "\n====================Test Failed==================== %s Failed" % instance.__class__.__name__)
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", 'failed'))
            finally:
                instance.do_teardown()


def runner(test_suite, test_config=None, testbed_config=None, report_config=None):
    module = load_module_from_file(test_suite)
    results = []
    for name, cls in inspect.getmembers(module, inspect.isclass):
        if cls.__module__ == module.__name__:
            log.info(f"\nRunning class: {name}")
            run_class(cls, results, test_config)
    if CONNECTION_POOL is not None:
        CONNECTION_POOL.close_all()
    HTMLReportGenerator(results, title="Radius Tests Report").generate("radius_report.html")
    json_results = [result.__dict__ for result in results]
    with open("radius_report.json", "w", encoding="utf-8") as json_file:
        json.dump(json_results, json_file, indent=4)


if __name__ == "__main__":
    runner("test/radius/radius_test.py")
