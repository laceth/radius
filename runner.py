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

def collect_test_classes(test_suite):
    """
    Identify and return the module and a list of test classes from the test_suite string.

    Args:
        test_suite (str): Path to the test file, optionally suffixed with ::ClassName

    Returns:
        tuple: (module, list_of_classes)
    """
    #TODO: define rules of config file mapping would allow calling multiple testsuite files and collecting all tests.
    single_test_class_name = None
    file_path = test_suite

    if "::" in test_suite:
        file_path, single_test_class_name = test_suite.split("::")

    module = load_module_from_file(file_path)
    collected_classes = []

    for name, cls in inspect.getmembers(module, inspect.isclass):
        if name.startswith('_'):
            continue  # skip private classes
        if cls.__module__ == module.__name__:
            if single_test_class_name and name != single_test_class_name:
                continue
            collected_classes.append(cls)

    return module, collected_classes


def get_objects_from_classes(collected_classes, test_config, log_dir_path=None):
    """
    Create instances from test classes using the Configurator, handling parametrization.
    Similar to run_class but stops after instantiation.

    Args:
        collected_classes (list): List of test classes.
        test_config (str): Path to test configuration.
        log_dir_path (str, optional): Log directory path to inject into instances.

    Returns:
        list: A list of instantiated test objects.
    """
    objects = []
    configurator = Configurator(test_config)

    for cls in collected_classes:
        param_data = getattr(cls, "_parametrize_args", None)

        if not param_data:
            try:
                instance = configurator.inject(cls, configurator.eyesight_config())
                instance.test_log_dir = log_dir_path
                objects.append(instance)
            except Exception as e:
                log.error(f"Error creating instance for {cls.__name__}: {str(e)}")
        else:
            arg_names, arg_values_list = param_data
            for idx, values in enumerate(arg_values_list, 1):
                try:
                    instance = configurator.inject(cls, configurator.eyesight_config())
                    instance.test_log_dir = log_dir_path
                    instance.test_params = {}
                    wrapped = [values] if isinstance(values, (str, int, float, bool)) else values
                    kwargs = dict(zip(arg_names, wrapped))
                    for k, v in kwargs.items():
                        instance.test_params[k] = v

                    objects.append(instance)
                except Exception as e:
                    log.error(f"Error creating parametrized instance for {cls.__name__} with {values}: {str(e)}")
    return objects


def run_tests(objects, results):
    """
    Execute lifecycle (setup, test, teardown) for a list of test objects.
    Runs suite_setup once at the start (from the first object) and suite_teardown once at the end.

    Args:
        objects (list): List of instantiated test objects.
        results (list): List to append test results to.
    """
    if not objects:
        log.info("No test collected to run.")
        return

    # 1. SUITE SETUP (Run once for the whole list, using the first available instance)
    # Since all objects share the same setup logic, we use the first instance as the driver.
    first_instance = objects[0]
    if hasattr(first_instance, "suite_setup"):
        try:
            log.info(DEFAULT_DECORATE_FORMAT.format("Running Suite Setup"))
            first_instance.suite_setup()
        except Exception as e:
            raise Exception(f"Aborting test run due to suite setup failure: {e}")


    # 2. TEST LIFECYCLE (Iterate all objects)
    for instance in objects:
        cls_name = instance.__class__.__name__
        test_name = cls_name
        if hasattr(instance, "test_params") and instance.test_params:
            test_name = f"{cls_name} with {instance.test_params}"
            log.info(test_name)

        try:
            instance.do_setup()
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Running test: {test_name}"))
            instance.do_test()
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Test passed: {test_name} Passed"))
            results.append(TestResult(test_name, 'passed'))
        except (AssertionError, Exception) as e:
            log.error(DEFAULT_DECORATE_FORMAT.format(f"Test Failed: {test_name} Failed"))
            log.error(f"Error: {str(e)}")
            results.append(TestResult(test_name, 'failed', str(e)))
        finally:
            instance.do_teardown()

    # 3. SUITE TEARDOWN (Run once at the end)
    if hasattr(first_instance, "suite_teardown"):
        try:
            log.info(DEFAULT_DECORATE_FORMAT.format("Running Suite Teardown"))
            first_instance.suite_teardown()
        except Exception as e:
            log.error(f"Suite Teardown Failed: {e}")


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


def _flush_report(results, report_name, log_dir_path=None):
    """Write HTML and JSON reports with current results.

    report_name may be a bare stem ("radius_report"), a name with a known
    extension ("radius_report.html"), or a full path ("/tmp/out/report").
    The extension is always stripped so we control it; when only a basename is
    given (no directory component) the files are placed inside log_dir_path.
    """
    stem, ext = os.path.splitext(report_name)
    if ext.lower() in (".html", ".json"):
        report_name = stem

    if log_dir_path and not os.path.dirname(report_name):
        base = os.path.join(log_dir_path, report_name)
    else:
        base = report_name

    HTMLReportGenerator(results, title="Radius Tests Report").generate(f"{base}.html")
    json_results = [result.__dict__ for result in results]
    with open(f"{base}.json", "w", encoding="utf-8") as json_file:
        json.dump(json_results, json_file, indent=4)


def run_class(cls, results, test_config, log_dir_path=None, report_name=None):
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
            if report_name:
                _flush_report(results, report_name, log_dir_path)
    else:
        log.info(DEFAULT_DECORATE_FORMAT.format(f"Running Parametrized test {cls.__name__}"))
        arg_names, arg_values_list = param_data
        for idx, values in enumerate(arg_values_list, 1):
            test_name = f"{cls.__name__}[{idx}] with {values}"
            instance = configurator.inject(cls, configurator.eyesight_config())
            instance.test_log_dir = log_dir_path
            instance.test_params = {}
            log.info(DEFAULT_DECORATE_FORMAT.format(f"Running {test_name}"))
            wrapped = [values] if isinstance(values, (str, int, float, bool)) else values
            kwargs = dict(zip(arg_names, wrapped))
            for k, v in kwargs.items():
                instance.test_params[k] = v
            try:
                instance.do_setup()
                log.info(DEFAULT_DECORATE_FORMAT.format(f"Running test: {test_name}"))
                instance.do_test()
                log.info(DEFAULT_DECORATE_FORMAT.format(f"Test passed: {test_name} Passed"))
                results.append(TestResult(test_name, 'passed'))
            except (AssertionError, Exception) as e:
                log.error(DEFAULT_DECORATE_FORMAT.format(f"Test Failed: {test_name} Failed"))
                log.error(f"Error: {str(e)}")
                results.append(TestResult(test_name, 'failed', str(e)))
            finally:
                instance.do_teardown()
                if report_name:
                    _flush_report(results, report_name, log_dir_path)


def runner(test_suite, test_config=None, testbed_config=None, report_config=None):
    results = []
    log_dir_path = set_up_logging() # Ensure we have a valid log directory
    module, test_classes = collect_test_classes(test_suite)
    tests = get_objects_from_classes(test_classes, test_config, log_dir_path=log_dir_path)
    run_tests(tests, results)
    if CONNECTION_POOL is not None:
        CONNECTION_POOL.close_all()
    if report_config:
        _flush_report(results, report_config, log_dir_path)


if __name__ == "__main__":
    runner("my_test.py","my_test_config.yaml", report_config="my_test_report")
