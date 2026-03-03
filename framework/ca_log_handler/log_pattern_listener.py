import threading
import time
import re

class PatternWatcher:
    def __init__(self, patterns, timeout=30):
        self.patterns = [re.compile(p) for p in patterns]
        self.remaining = set(range(len(patterns)))
        self.timeout = timeout
        self.event = threading.Event()
        self.matched_lines = {}
        self.start_time = time.time()
        self.lock = threading.Lock() # For thread safety if multiple threads access result

    def check_log_pattern(self, line):
        """Check the line against remaining patterns."""
        with self.lock:
            if self.event.is_set():
                return

            matched_indices = []
            for idx in self.remaining:
                if self.patterns[idx].search(line):
                    self.matched_lines[idx] = line.strip()
                    matched_indices.append(idx)

            for idx in matched_indices:
                self.remaining.remove(idx)

            if not self.remaining:
                self.event.set()

    def is_finished(self):
        return self.event.is_set()

    def get_result(self):
        """
        Returns:
            (bool, dict): (True if all patterns matched within timeout, matched_lines)
        """
        with self.lock:
            is_success = self.event.is_set()

            if not is_success and (time.time() - self.start_time > self.timeout):
                return False, self.matched_lines.copy()

            return is_success, self.matched_lines.copy()
