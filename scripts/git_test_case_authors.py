"""
Finds who authored each test case class (the `class XxxTest(...)` line)
using git blame across both repos.
"""
import subprocess
import os
import re
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NEW_REPO = os.path.dirname(SCRIPT_DIR)
OLD_REPO = os.path.join(os.path.dirname(NEW_REPO), "fstester")

# Base classes are not test cases
BASE_CLASSES = {
    "RadiusTestBase", "RadiusCertificatesTestBase", "RadiusEapTlsTestBase",
    "RadiusMabTestBase", "RadiusPeapEapTlsTestBase", "RadiusPeapTestBase",
    "TestBase",
}
# Example / scaffold classes (not real test cases)
EXAMPLE_CLASSES = {
    "ExamplePositiveTest", "NegativeExampleTest",
    "RadiusTestCommanExample", "RadiusTestSpecialSetupExample",
    "RadiusTestPrametrized",
}


def run_git(repo_dir, *args):
    r = subprocess.run(
        ["git", "--no-pager"] + list(args),
        capture_output=True, text=True, cwd=repo_dir, encoding="utf-8",
    )
    return r.stdout


def find_test_classes(repo_dir):
    """Walk test files and return [(filepath, line_no, class_name, tc_id), ...]"""
    results = []
    tests_dir = os.path.join(repo_dir, "tests")
    if not os.path.isdir(tests_dir):
        return results
    for root, _, files in os.walk(tests_dir):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir).replace("\\", "/")
            try:
                with open(fpath, encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                m = re.match(r"^class\s+(\w+)\s*\(", line)
                if m:
                    cls_name = m.group(1)
                    if cls_name in BASE_CLASSES or cls_name in EXAMPLE_CLASSES:
                        continue
                    if not re.search(r"Test", cls_name):
                        continue
                    # look for TC id in docstring (next few lines)
                    tc_id = ""
                    for j in range(i + 1, min(i + 5, len(lines))):
                        tm = re.search(r"(T\d{7})", lines[j])
                        if tm:
                            tc_id = tm.group(1)
                            break
                    results.append((rel, i + 1, cls_name, tc_id))
    return results


def blame_line(repo_dir, filepath, line_no):
    """Return author email for a specific line via git blame."""
    out = run_git(repo_dir, "blame", "-L", f"{line_no},{line_no}",
                  "--line-porcelain", filepath)
    for l in out.splitlines():
        if l.startswith("author-mail"):
            return l.split("<")[1].rstrip(">")
    return "unknown"


def main():
    all_cases = []

    for repo_dir, label in [(OLD_REPO, "fstester"), (NEW_REPO, "fsct-fstester")]:
        classes = find_test_classes(repo_dir)
        for rel, line_no, cls_name, tc_id in classes:
            email = blame_line(repo_dir, rel, line_no)
            all_cases.append({
                "repo": label,
                "file": rel,
                "class": cls_name,
                "tc_id": tc_id,
                "author": email,
            })

    # Deduplicate: if same class name exists in both repos, keep only fsct-fstester
    seen = set()
    deduped = []
    # Process new repo first so it wins
    for c in sorted(all_cases, key=lambda x: (0 if x["repo"] == "fsct-fstester" else 1)):
        if c["class"] not in seen:
            seen.add(c["class"])
            deduped.append(c)

    # Print detailed list
    print(f"\n{'='*80}")
    print(f" Test Cases by Author (deduplicated across repos)")
    print(f"{'='*80}\n")

    by_author = defaultdict(list)
    for c in deduped:
        by_author[c["author"]].append(c)

    for author in sorted(by_author, key=lambda a: len(by_author[a]), reverse=True):
        cases = by_author[author]
        print(f"\n{author}: {len(cases)} test case(s)")
        for c in sorted(cases, key=lambda x: x["class"]):
            tc = f" [{c['tc_id']}]" if c["tc_id"] else ""
            print(f"  - {c['class']}{tc}  ({c['repo']}: {c['file']})")

    print(f"\n{'='*80}")
    print(f" TOTAL: {len(deduped)} unique test cases")
    print(f"{'='*80}")

    # Output as markdown table snippet for insertion into GIT_STATISTICS.md
    md_lines = []
    md_lines.append("")
    md_lines.append("## 13. Test Cases Authored per Contributor")
    md_lines.append("")
    md_lines.append("| # | Test Case Class | Test ID | Author | Repo | File |")
    md_lines.append("|---|-----------------|---------|--------|------|------|")
    for idx, c in enumerate(sorted(deduped, key=lambda x: (x["author"], x["class"])), 1):
        md_lines.append(
            f"| {idx} | `{c['class']}` | {c['tc_id'] or '-'} | `{c['author']}` | {c['repo']} | `{c['file']}` |"
        )
    md_lines.append("")

    # Summary sub-table
    md_lines.append("### Test Case Count by Author")
    md_lines.append("")
    md_lines.append("| Author | Test Cases Authored |")
    md_lines.append("|--------|---------------------|")
    for author in sorted(by_author, key=lambda a: len(by_author[a]), reverse=True):
        md_lines.append(f"| `{author}` | {len(by_author[author])} |")
    md_lines.append("")

    md_snippet = "\n".join(md_lines)
    print(md_snippet)

    # Append to GIT_STATISTICS.md
    stat_path = os.path.join(NEW_REPO, "GIT_STATISTICS.md")
    with open(stat_path, "a", encoding="utf-8-sig") as f:
        f.write(md_snippet)
    print(f"\nAppended section 13 to {stat_path}")


if __name__ == "__main__":
    main()

