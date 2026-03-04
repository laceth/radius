import datetime
import importlib.util
import inspect
import json
import logging
import os
import sys
from framework.configurator.configurator import Configurator
from framework.connection.connection_pool import CONNECTION_POOL
from framework.log.logger import log
from framework.report.html_report import HTMLReportGenerator
from framework.report.test_result import TestResult

DEFAULT_DECORATE_FORMAT = "\n{:=^200}\n"

def load_module_from_file(filepath):
    """Load a Python file as a module dynamically"""
    module_name = os.path.splitext(os.path.basename(filepath))[0]
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def set_up_logging(log_level="info", log_dir="./logs"):
    """Set up logging configuration.
    :param log_level: Logging level (default: info)
    :param log_dir: Base directory to create the timestamped log folder (default: None)
    :return: The path to the created log directory
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    log.setLevel(numeric_level)

    # Clear existing handlers to prevent duplicates and close them properly
    for handler in list(log.handlers):
        log.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)

    # File Handler logic
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_folder_name = f"fstester_log_{timestamp}"
    log_path = os.path.join(log_dir, log_folder_name)

    if not os.path.exists(log_path):
        os.makedirs(log_path)

    file_path = os.path.join(log_path, "fstester.log")
    file_handler = logging.FileHandler(file_path, encoding='utf-8')
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    return log_path


def run_class(cls, results, test_config, log_dir_path):
    """Run all test methods in a class"""
    param_data = getattr(cls, "_parametrize_args", None)
    configurator = Configurator(test_config)
    if not param_data:
        try:
            # TODO: As the framework evolves, the injection logic should be separated into distinct responsibilities; we are keeping it simple for now.
            instance = configurator.inject(cls, configurator.eyesight_config())
            #inject base log dir path to testcases.
            instance.test_log_dir = log_dir_path
            instance.do_setup()
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Running test: {instance.__class__.__name__}"))
            instance.do_test()
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Test passed: {instance.__class__.__name__} Passed"))
            results.append(TestResult(cls.__name__, 'passed'))
        except (AssertionError, Exception) as e:
            log.error(DEFAULT_DECORATE_FORMAT.format(f"Test Failed: {instance.__class__.__name__} Failed"))
            log.error(f"Error: {str(e)}")
            results.append(TestResult(cls.__name__, 'failed', str(e)))
        finally:
            instance.do_teardown()
    else:
        log.info(DEFAULT_DECORATE_FORMAT.format(f"Running Parametrized test {cls.__name__}"))
        arg_names, arg_values_list = param_data
        for idx, values in enumerate(arg_values_list, 1):
            instance = configurator.inject(cls, configurator.eyesight_config())
            instance.test_log_dir = log_dir_path
            instance.test_params = {}
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Running {cls.__name__}[{idx}] with {values}"))
            kwargs = dict(zip(arg_names, values))
            for k, v in kwargs.items():
                instance.test_params[k] = v
            try:
                instance.do_setup()
                log.info(DEFAULT_DECORATE_FORMAT.format(f"Running test: {cls.__name__}[{idx}]"))
                instance.do_test()
                log.info(DEFAULT_DECORATE_FORMAT.format(f"Test passed: {instance.__class__.__name__} Passed"))
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", 'passed'))
            except (AssertionError, Exception) as e:
                log.error(DEFAULT_DECORATE_FORMAT.format(f"Test Failed: {instance.__class__.__name__} Failed"))
                log.error(f"Error: {str(e)}")
                results.append(TestResult(f"{cls.__name__}[{idx}]with {values}", 'failed', str(e)))
            finally:
                instance.do_teardown()


def runner(test_suite, test_config=None, testbed_config=None, report_config=None):
    log_dir_path = set_up_logging(log_level="info")
    results = []
    single_test_class = False
    if "::" in test_suite:
        single_test_class = True
        module = load_module_from_file(test_suite.split("::")[0])

    else:
        module = load_module_from_file(test_suite)

    for name, cls in inspect.getmembers(module, inspect.isclass):
        if cls.__module__ == module.__name__:
            if single_test_class and name != test_suite.split("::")[-1]:
                continue
            log.info(f"\nRunning class: {name}")
            run_class(cls, results, test_config, log_dir_path)
    if CONNECTION_POOL is not None:
        CONNECTION_POOL.close_all()

    HTMLReportGenerator(results, title="Radius Tests Report").generate(os.path.join(log_dir_path, "report.html"))
    json_results = [result.__dict__ for result in results]
    with open("radius_report.json", "w", encoding="utf-8") as json_file:
        json.dump(json_results, json_file, indent=4)


if __name__ == "__main__":
    runner("test/radius/radius_test.py")
