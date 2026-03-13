"""
Combined Git Statistics Generator for fstester + fsct-fstester

Reads git history from both repos, deduplicates the initial copy-paste
commit (AA-848: Initial commit), and produces a unified statistics doc.

Usage:  python scripts/git_stats_combined.py
"""
import re
import subprocess
import os
from collections import defaultdict
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NEW_REPO = os.path.dirname(SCRIPT_DIR)  # fsct-fstester
OLD_REPO = os.path.join(os.path.dirname(NEW_REPO), "fstester")

# The two "AA-848: Initial commit" hashes in fsct-fstester that are just a
# copy-paste of the old repo state. We skip them so lines aren't double-counted.
COPY_PASTE_HASHES = {
    "c58a620b255f494231cafd8082ffa71861126f9e",
    "1195eec8a17e5e0547aae954bb7d1b9b18e5a68e",
}


def run_git(repo_dir, *args):
    result = subprocess.run(
        ["git", "--no-pager"] + list(args),
        capture_output=True, text=True, cwd=repo_dir, encoding="utf-8",
    )
    return result.stdout


# ═══════════════════════════════════════════════════════════════════════
#  Core data collection
# ═══════════════════════════════════════════════════════════════════════

def _parse_numstat_log(repo_dir, repo_label, skip_hashes=None):
    """Return a list of commit dicts from one repo."""
    skip_hashes = skip_hashes or set()
    raw = run_git(
        repo_dir,
        "log", "--all", "--format=COMMIT_SEP%n%H%n%ae%n%ai%n%s", "--numstat",
    )
    commits = []
    cur = None
    field_idx = 0  # tracks which metadata field we're filling next

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped == "COMMIT_SEP":
            if cur and cur["hash"] not in skip_hashes:
                commits.append(cur)
            cur = {
                "hash": None, "email": None, "date": None, "subject": None,
                "added": 0, "removed": 0, "files": set(), "repo": repo_label,
            }
            field_idx = 0
            continue

        if cur is None:
            continue

        # Fill metadata fields in order: hash → email → date → subject
        if field_idx == 0:
            cur["hash"] = stripped
            field_idx = 1
            continue
        if field_idx == 1:
            cur["email"] = stripped
            field_idx = 2
            continue
        if field_idx == 2:
            cur["date"] = stripped[:10]
            field_idx = 3
            continue
        if field_idx == 3:
            cur["subject"] = stripped
            field_idx = 4
            continue

        # numstat lines
        parts = stripped.split("\t")
        if len(parts) == 3:
            added, removed, fname = parts
            if added != "-":
                cur["added"] += int(added)
            if removed != "-":
                cur["removed"] += int(removed)
            cur["files"].add(fname)

    if cur and cur["hash"] not in skip_hashes:
        commits.append(cur)

    return commits


def gather_all():
    """Collect commits from both repos, dedup the copy-paste."""
    old_commits = _parse_numstat_log(OLD_REPO, "fstester")
    new_commits = _parse_numstat_log(NEW_REPO, "fsct-fstester", skip_hashes=COPY_PASTE_HASHES)
    all_commits = old_commits + new_commits

    # ── aggregate per email ──
    stats = {}
    for c in all_commits:
        email = c["email"]
        if email not in stats:
            stats[email] = {
                "commits": 0, "lines_added": 0, "lines_removed": 0,
                "files_touched": set(),
                "first_commit": None, "last_commit": None,
                "repos": set(),
                "subjects": [],
            }
        s = stats[email]
        s["commits"] += 1
        s["lines_added"] += c["added"]
        s["lines_removed"] += c["removed"]
        s["files_touched"] |= c["files"]
        s["repos"].add(c["repo"])
        s["subjects"].append(c["subject"] or "")
        d = c["date"]
        if d:
            if s["first_commit"] is None or d < s["first_commit"]:
                s["first_commit"] = d
            if s["last_commit"] is None or d > s["last_commit"]:
                s["last_commit"] = d

    # ── tickets per email ──
    tickets = defaultdict(set)
    for c in all_commits:
        subj = c["subject"] or ""
        for m in re.finditer(r"(AA-\d+|T\d{7})", subj):
            tickets[c["email"]].add(m.group(1))

    # ── branches per email (both repos) ──
    branches = defaultdict(set)
    for repo_dir, label in [(OLD_REPO, "fstester"), (NEW_REPO, "fsct-fstester")]:
        branch_out = run_git(repo_dir, "branch", "-a", "--format=%(refname:short)")
        for br in branch_out.strip().splitlines():
            br = br.strip()
            if not br:
                continue
            email = run_git(repo_dir, "log", "-1", "--format=%ae", br).strip()
            if email:
                branches[email].add(f"[{label}] {br}")

    # ── weekly activity (combined) ──
    weeks = defaultdict(lambda: defaultdict(int))  # week -> email -> count
    weeks_total = defaultdict(int)
    for c in all_commits:
        d = c["date"]
        if d:
            try:
                dt = datetime.strptime(d, "%Y-%m-%d")
                iso = dt.isocalendar()
                wk = f"{iso[0]}-W{iso[1]:02d}"
                weeks[wk][c["email"]] += 1
                weeks_total[wk] += 1
            except ValueError:
                pass

    # ── per-repo commit counts ──
    repo_counts = {"fstester": len(old_commits), "fsct-fstester": len(new_commits)}

    return stats, tickets, branches, weeks, weeks_total, repo_counts, all_commits


# ═══════════════════════════════════════════════════════════════════════
#  Markdown generation
# ═══════════════════════════════════════════════════════════════════════

def build_markdown(stats, tickets, branches, weeks, weeks_total, repo_counts, all_commits):
    L = []
    add = L.append

    total_commits = sum(s["commits"] for s in stats.values())
    total_added = sum(s["lines_added"] for s in stats.values())
    total_removed = sum(s["lines_removed"] for s in stats.values())
    all_files = set()
    for s in stats.values():
        all_files |= s["files_touched"]

    all_dates = [c["date"] for c in all_commits if c["date"]]
    date_range_start = min(all_dates) if all_dates else "?"
    date_range_end = max(all_dates) if all_dates else "?"

    add("# Combined Git Repository Statistics")
    add("")
    add(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"**Repositories:** `fstester` (old) → `fsct-fstester` (current)")
    add(f"**Date Range:** {date_range_start} — {date_range_end}")
    add(f"**Note:** The initial copy-paste commit (AA-848) is counted only once to avoid double-counting.")
    add("")

    # ── Summary ──
    add("## 1. Overall Summary")
    add("")
    add("| Metric | Value |")
    add("|--------|-------|")
    add(f"| Total Contributors | {len(stats)} |")
    add(f"| Total Commits (combined, deduplicated) | {total_commits} |")
    add(f"| ↳ from `fstester` (old repo) | {repo_counts['fstester']} |")
    add(f"| ↳ from `fsct-fstester` (new repo, excl. copy-paste) | {repo_counts['fsct-fstester']} |")
    add(f"| Total Lines Added | {total_added:,} |")
    add(f"| Total Lines Removed | {total_removed:,} |")
    add(f"| Net Lines | {'+' if total_added - total_removed >= 0 else ''}{total_added - total_removed:,} |")
    add(f"| Unique Files Touched | {len(all_files)} |")
    add("")

    # ── Per-Author Table ──
    sorted_authors = sorted(stats.items(), key=lambda kv: kv[1]["commits"], reverse=True)

    add("## 2. Per-Author Breakdown")
    add("")
    add("| # | Email | Commits | Lines Added | Lines Removed | Net Lines | Files Touched | Active Period | Repos |")
    add("|---|-------|---------|-------------|---------------|-----------|---------------|---------------|-------|")
    for idx, (email, s) in enumerate(sorted_authors, 1):
        net = s["lines_added"] - s["lines_removed"]
        sign = "+" if net >= 0 else ""
        repos = ", ".join(sorted(s["repos"]))
        period = f"{s['first_commit']} → {s['last_commit']}"
        add(f"| {idx} | `{email}` | {s['commits']} | +{s['lines_added']:,} | "
            f"-{s['lines_removed']:,} | {sign}{net:,} | {len(s['files_touched'])} | {period} | {repos} |")
    add("")

    # ── Commit Share ──
    add("## 3. Commit Share")
    add("")
    add("| Email | Commits | Share |")
    add("|-------|---------|-------|")
    for email, s in sorted_authors:
        pct = (s["commits"] / total_commits) * 100 if total_commits else 0
        bar = "█" * int(pct / 2)
        add(f"| `{email}` | {s['commits']} | {pct:.1f}% {bar} |")
    add("")

    # ── Lines Added Share ──
    add("## 4. Lines Added Share")
    add("")
    add("| Email | Lines Added | Share |")
    add("|-------|-------------|-------|")
    for email, s in sorted(stats.items(), key=lambda kv: kv[1]["lines_added"], reverse=True):
        pct = (s["lines_added"] / total_added) * 100 if total_added else 0
        bar = "█" * int(pct / 2)
        add(f"| `{email}` | +{s['lines_added']:,} | {pct:.1f}% {bar} |")
    add("")

    # ── Lines Removed Share ──
    add("## 5. Lines Removed Share")
    add("")
    add("| Email | Lines Removed | Share |")
    add("|-------|---------------|-------|")
    for email, s in sorted(stats.items(), key=lambda kv: kv[1]["lines_removed"], reverse=True):
        pct = (s["lines_removed"] / total_removed) * 100 if total_removed else 0
        bar = "█" * int(pct / 2)
        add(f"| `{email}` | -{s['lines_removed']:,} | {pct:.1f}% {bar} |")
    add("")

    # ── Avg. Commit Size ──
    add("## 6. Average Commit Size (lines added per commit)")
    add("")
    add("| Email | Commits | Avg Lines Added/Commit | Avg Lines Removed/Commit |")
    add("|-------|---------|------------------------|--------------------------|")
    for email, s in sorted_authors:
        avg_a = s["lines_added"] / s["commits"] if s["commits"] else 0
        avg_r = s["lines_removed"] / s["commits"] if s["commits"] else 0
        add(f"| `{email}` | {s['commits']} | {avg_a:.0f} | {avg_r:.0f} |")
    add("")

    # ── Tickets ──
    add("## 7. Tickets / Work Items per Author")
    add("")
    add("| Email | # Tickets | Tickets |")
    add("|-------|-----------|---------|")
    for email, _ in sorted_authors:
        tix = sorted(tickets.get(email, set()))
        add(f"| `{email}` | {len(tix)} | {', '.join(tix) if tix else '—'} |")
    add("")

    # ── Branches ──
    add("## 8. Branches by Last Author (both repos)")
    add("")
    add("| Email | Branches |")
    add("|-------|----------|")
    for email, brs in sorted(branches.items()):
        add(f"| `{email}` | {', '.join(sorted(brs))} |")
    add("")

    # ── Weekly Activity ──
    add("## 9. Weekly Commit Activity")
    add("")
    add("| Week | Total | " + " | ".join(f"`{e}`" for e, _ in sorted_authors) + " |")
    add("|------|-------| " + " | ".join("---" for _ in sorted_authors) + " |")
    for wk in sorted(weeks_total):
        row = f"| {wk} | {weeks_total[wk]} |"
        for email, _ in sorted_authors:
            cnt = weeks[wk].get(email, 0)
            cell = str(cnt) if cnt else ""
            row += f" {cell} |"
        add(row)
    add("")

    # ── Weekly Activity Visual ──
    add("## 10. Weekly Activity (visual)")
    add("")
    add("| Week | Commits |")
    add("|------|---------|")
    for wk in sorted(weeks_total):
        bar = "█" * weeks_total[wk]
        add(f"| {wk} | {weeks_total[wk]} {bar} |")
    add("")

    # ── Monthly Summary ──
    add("## 11. Monthly Summary")
    add("")
    months = defaultdict(lambda: {"commits": 0, "added": 0, "removed": 0})
    for c in all_commits:
        d = c["date"]
        if d:
            m_key = d[:7]  # YYYY-MM
            months[m_key]["commits"] += 1
            months[m_key]["added"] += c["added"]
            months[m_key]["removed"] += c["removed"]
    add("| Month | Commits | Lines Added | Lines Removed | Net |")
    add("|-------|---------|-------------|---------------|-----|")
    for m in sorted(months):
        md = months[m]
        net = md["added"] - md["removed"]
        add(f"| {m} | {md['commits']} | +{md['added']:,} | -{md['removed']:,} | {'+' if net >= 0 else ''}{net:,} |")
    add("")

    # ── Top files by churn ──
    add("## 12. Top 20 Most-Changed Files (by total lines added + removed)")
    add("")
    file_churn = defaultdict(lambda: {"added": 0, "removed": 0, "touches": 0})
    for c in all_commits:
        # Re-parse is expensive; let's at least count touches per file
        for f in c["files"]:
            file_churn[f]["touches"] += 1
    # We only tracked file names per commit, not per-file line counts in the
    # aggregate.  Let's collect that properly.
    file_churn2 = defaultdict(lambda: {"added": 0, "removed": 0, "touches": 0})
    for repo_dir, label, skip in [
        (OLD_REPO, "fstester", set()),
        (NEW_REPO, "fsct-fstester", COPY_PASTE_HASHES),
    ]:
        raw = run_git(repo_dir, "log", "--all", "--format=COMMIT_SEP%n%H", "--numstat")
        cur_hash = None
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == "COMMIT_SEP":
                cur_hash = None
                continue
            if cur_hash is None:
                cur_hash = stripped
                continue
            if cur_hash in skip:
                continue
            parts = stripped.split("\t")
            if len(parts) == 3:
                a, r, fname = parts
                key = f"[{label}] {fname}"
                if a != "-":
                    file_churn2[key]["added"] += int(a)
                if r != "-":
                    file_churn2[key]["removed"] += int(r)
                file_churn2[key]["touches"] += 1

    top_files = sorted(file_churn2.items(), key=lambda kv: kv[1]["added"] + kv[1]["removed"], reverse=True)[:20]
    add("| # | File | Lines Added | Lines Removed | Total Churn | Touches |")
    add("|---|------|-------------|---------------|-------------|---------|")
    for idx, (fname, fc) in enumerate(top_files, 1):
        add(f"| {idx} | `{fname}` | +{fc['added']:,} | -{fc['removed']:,} | {fc['added'] + fc['removed']:,} | {fc['touches']} |")
    add("")

    return "\n".join(L)


def main():
    if not os.path.isdir(OLD_REPO):
        print(f"ERROR: Old repo not found at {OLD_REPO}")
        return
    if not os.path.isdir(NEW_REPO):
        print(f"ERROR: New repo not found at {NEW_REPO}")
        return

    stats, tickets, branches, weeks, weeks_total, repo_counts, all_commits = gather_all()
    md = build_markdown(stats, tickets, branches, weeks, weeks_total, repo_counts, all_commits)

    out_path = os.path.join(NEW_REPO, "GIT_STATISTICS.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Combined statistics written to {out_path}")
    print(f"  Old repo commits:  {repo_counts['fstester']}")
    print(f"  New repo commits:  {repo_counts['fsct-fstester']}")
    print(f"  Skipped (copy-paste): {len(COPY_PASTE_HASHES)}")


if __name__ == "__main__":
    main()

