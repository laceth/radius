import argparse
import sys

from runner import runner

def main():
    parser = argparse.ArgumentParser(description="Run the test suite.")
    parser.add_argument("-t", "--test-suite", required=True, help="Path to the test suite file.")
    parser.add_argument("-config", "--config-file", required=False, help="Path to the configuration file.")
    args = parser.parse_args()

    runner(args.test_suite, test_config=args.config_file)

if __name__ == "__main__":
    main()