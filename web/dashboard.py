import json
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DATA_FILE = Path("test_results.json")

# Load existing submissions
if DATA_FILE.exists():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        submissions = json.load(f)
else:
    submissions = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Test Results Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .passed { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        .skipped { color: orange; font-weight: bold; }
        .submission-header { cursor: pointer; background-color: #e0e0e0; padding: 10px; margin-bottom: 5px; font-weight: bold; }
        .submission-body { display: none; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Test Results Dashboard</h1>
    {% for s in submissions %}
        <div class="submission-header" onclick="toggleSubmission('sub{{ loop.index }}')">
            Submission at: {{ s.timestamp }} ({{ s.results|length }} tests)
        </div>
        <div class="submission-body" id="sub{{ loop.index }}">
            <table>
                <thead>
                    <tr><th>Test Name</th><th>Status</th><th>Details</th></tr>
                </thead>
                <tbody>
                    {% for r in s.results %}
                    <tr>
                        <td>{{ r.test_name }}</td>
                        <td class="{{ r.status }}">{{ r.status.upper() }}</td>
                        <td>{{ r.details or "-" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    {% endfor %}

    <script>
        function toggleSubmission(id) {
            var elem = document.getElementById(id);
            if (elem.style.display === "none") {
                elem.style.display = "block";
            } else {
                elem.style.display = "none";
            }
        }
    </script>
</body>
</html>
"""


@app.route("/submit", methods=["POST"])
def submit_results():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "JSON must be a list of test results"}), 400
    for item in data:
        if not all(k in item for k in ("test_name", "status")):
            return jsonify({"error": "Each test result must have 'test_name' and 'status'"}), 400

    submission = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": data}
    submissions.append(submission)

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(submissions, f, indent=2)

    return jsonify({"message": "Test results submitted", "count": len(data)}), 200


@app.route("/")
def show_results():
    # Newest submissions first
    sorted_submissions = sorted(submissions, key=lambda x: x["timestamp"], reverse=True)
    return render_template_string(HTML_TEMPLATE, submissions=sorted_submissions)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
