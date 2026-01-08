import argparse

from runner import runner


def main():
    parser = argparse.ArgumentParser(description="Run the test suite.")
    parser.add_argument("-t", "--test-suite", required=True, help="Path to the test suite file.")
    parser.add_argument("-config", "--config-file", required=False, help="Path to the configuration file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity.")
    parser.add_argument("-debug", choices=["debug", "info", "warning", "error"], default="info", help="Log level.")
    parser.add_argument("-l", "--log-file", required=False, help="Path to the log file.")
    parser.add_argument("-report", "--report-file", required=False, help="Path to the report file.")
    parser.add_argument("-ctlog", "--ctlog-file", required=False, help="Path to the ctlog file.")
    parser.add_argument("-u", "--update-result", required=False, help="Update the report to portal")
    parser.add_argument("--case", required=False, help="Run a specific test class name (exact or substring).")
    parser.add_argument("-k", "--keyword", required=False, help="Substring filter for test class names.")
    parser.add_argument("-m", "--markers", required=False, help="Marker expression, e.g. 'smoke', 'regression and not slow'.")
    args = parser.parse_args()
    runner(args.test_suite, test_config=args.config_file, case=args.case, keyword=args.keyword, markers=args.markers)


if __name__ == "__main__":
    main()
