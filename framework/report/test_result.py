class TestResult:
    def __init__(self, test_name, status, details=None):
        self.test_name = test_name
        self.status = status  # 'passed', 'failed', 'skipped'
        self.details = details
        self.logs = []

    def __repr__(self):
        return f"TestResult(test_name={self.test_name}, status={self.status}, details={self.details})"
