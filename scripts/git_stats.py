"""
Git Statistics Generator
Reads git log from stdin and produces per-author metrics.
Usage:  git log --all --format="%ae" --numstat | python scripts/git_stats.py
"""
import sys
import subprocess
import os
import json
from collections import defaultdict
from datetime import datetime

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_git(*args):
    result = subprocess.run(
        ["git", "--no-pager"] + list(args),
        capture_output=True, text=True, cwd=REPO_DIR, encoding="utf-8"
    )
    return result.stdout


def gather_stats():
    # ── 1. Per-email: commits, lines added/removed, files touched, first/last date ──
    log_output = run_git(
        "log", "--all", "--format=COMMIT_SEP%n%ae%n%ai", "--numstat"
    )

    stats = {}
    current_email = None
    current_date = None

    for line in log_output.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        if line_s == "COMMIT_SEP":
            current_email = None
            current_date = None
            continue

        if current_email is None:
            current_email = line_s
            if current_email not in stats:
                stats[current_email] = {
                    "commits": 0,
                    "lines_added": 0,
                    "lines_removed": 0,
                    "files_touched": set(),
                    "first_commit": None,
                    "last_commit": None,
                }
            stats[current_email]["commits"] += 1
            continue

        if current_date is None:
            # date line like "2026-02-05 12:08:58 -0600"
            current_date = line_s[:10]  # YYYY-MM-DD
            rec = stats[current_email]
            if rec["first_commit"] is None or current_date < rec["first_commit"]:
                rec["first_commit"] = current_date
            if rec["last_commit"] is None or current_date > rec["last_commit"]:
                rec["last_commit"] = current_date
            continue

        parts = line_s.split("\t")
        if len(parts) == 3:
            added, removed, fname = parts
            rec = stats[current_email]
            if added != "-":
                rec["lines_added"] += int(added)
            if removed != "-":
                rec["lines_removed"] += int(removed)
            rec["files_touched"].add(fname)

    # ── 2. Merge emails that share the same @domain user (same person) ──
    merged = {}
    for email, s in stats.items():
        key = email  # keep individual emails (no merging)
        if key not in merged:
            merged[key] = {
                "commits": 0,
                "lines_added": 0,
                "lines_removed": 0,
                "files_touched": set(),
                "first_commit": None,
                "last_commit": None,
            }
        m = merged[key]
        m["commits"] += s["commits"]
        m["lines_added"] += s["lines_added"]
        m["lines_removed"] += s["lines_removed"]
        m["files_touched"] |= s["files_touched"]
        if m["first_commit"] is None or (s["first_commit"] and s["first_commit"] < m["first_commit"]):
            m["first_commit"] = s["first_commit"]
        if m["last_commit"] is None or (s["last_commit"] and s["last_commit"] > m["last_commit"]):
            m["last_commit"] = s["last_commit"]

    # ── 3. Branch counts per email ──
    branch_output = run_git("branch", "-a", "--format=%(refname:short)")
    branch_authors = defaultdict(set)
    for branch in branch_output.strip().splitlines():
        branch = branch.strip()
        if not branch:
            continue
        # Get the last committer email on this branch
        email_out = run_git("log", "-1", "--format=%ae", branch).strip()
        if email_out:
            branch_authors[email_out].add(branch)

    # ── 4. Ticket IDs per email ──
    ticket_log = run_git("log", "--all", "--format=%ae||%s")
    tickets_per_email = defaultdict(set)
    import re
    for line in ticket_log.strip().splitlines():
        if "||" not in line:
            continue
        email, subject = line.split("||", 1)
        # Pattern: AA-NNN or T followed by digits
        for m in re.finditer(r"(AA-\d+|T\d{7})", subject):
            tickets_per_email[email].add(m.group(1))

    return merged, branch_authors, tickets_per_email


def build_markdown(merged, branch_authors, tickets_per_email):
    lines = []
    lines.append("# Git Repository Statistics")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Repository:** fsct-fstester")
    lines.append("")

    total_commits = sum(s["commits"] for s in merged.values())
    total_added = sum(s["lines_added"] for s in merged.values())
    total_removed = sum(s["lines_removed"] for s in merged.values())
    all_files = set()
    for s in merged.values():
        all_files |= s["files_touched"]

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Contributors | {len(merged)} |")
    lines.append(f"| Total Commits | {total_commits} |")
    lines.append(f"| Total Lines Added | {total_added:,} |")
    lines.append(f"| Total Lines Removed | {total_removed:,} |")
    lines.append(f"| Total Unique Files | {len(all_files)} |")
    lines.append("")

    # ── Per-Author Table ──
    lines.append("## Per-Author Breakdown")
    lines.append("")
    lines.append(
        "| # | Email | Commits | Lines Added | Lines Removed | Net Lines | Files Touched | First Commit | Last Commit |"
    )
    lines.append(
        "|---|-------|---------|-------------|---------------|-----------|---------------|--------------|-------------|"
    )

    sorted_authors = sorted(merged.items(), key=lambda kv: kv[1]["commits"], reverse=True)
    for idx, (email, s) in enumerate(sorted_authors, 1):
        net = s["lines_added"] - s["lines_removed"]
        sign = "+" if net >= 0 else ""
        lines.append(
            f"| {idx} | {email} | {s['commits']} | +{s['lines_added']:,} | -{s['lines_removed']:,} | {sign}{net:,} | {len(s['files_touched'])} | {s['first_commit']} | {s['last_commit']} |"
        )
    lines.append("")

    # ── Commit Share ──
    lines.append("## Commit Share (%)")
    lines.append("")
    lines.append("| Email | Commits | Share |")
    lines.append("|-------|---------|-------|")
    for email, s in sorted_authors:
        pct = (s["commits"] / total_commits) * 100 if total_commits else 0
        bar = "█" * int(pct / 2)
        lines.append(f"| {email} | {s['commits']} | {pct:.1f}% {bar} |")
    lines.append("")

    # ── Lines-of-Code Share ──
    lines.append("## Lines Added Share (%)")
    lines.append("")
    lines.append("| Email | Lines Added | Share |")
    lines.append("|-------|-------------|-------|")
    for email, s in sorted(merged.items(), key=lambda kv: kv[1]["lines_added"], reverse=True):
        pct = (s["lines_added"] / total_added) * 100 if total_added else 0
        bar = "█" * int(pct / 2)
        lines.append(f"| {email} | +{s['lines_added']:,} | {pct:.1f}% {bar} |")
    lines.append("")

    # ── Tickets / Work Items per Author ──
    lines.append("## Tickets / Work Items per Author")
    lines.append("")
    lines.append("| Email | # Tickets | Tickets |")
    lines.append("|-------|-----------|---------|")
    for email, _ in sorted_authors:
        tix = sorted(tickets_per_email.get(email, set()))
        lines.append(f"| {email} | {len(tix)} | {', '.join(tix) if tix else '—'} |")
    lines.append("")

    # ── Branches ──
    lines.append("## Active Branches by Last Author")
    lines.append("")
    lines.append("| Email | Branches |")
    lines.append("|-------|----------|")
    for email, branches in sorted(branch_authors.items()):
        lines.append(f"| {email} | {', '.join(sorted(branches))} |")
    lines.append("")

    # ── Activity Timeline (commits per week) ──
    lines.append("## Weekly Activity (all authors)")
    lines.append("")
    week_log = run_git("log", "--all", "--format=%ai")
    weeks = defaultdict(int)
    for line in week_log.strip().splitlines():
        d = line.strip()[:10]
        try:
            dt = datetime.strptime(d, "%Y-%m-%d")
            iso = dt.isocalendar()
            week_key = f"{iso[0]}-W{iso[1]:02d}"
            weeks[week_key] += 1
        except ValueError:
            pass
    lines.append("| Week | Commits |")
    lines.append("|------|---------|")
    for w in sorted(weeks):
        bar = "█" * weeks[w]
        lines.append(f"| {w} | {weeks[w]} {bar} |")
    lines.append("")

    return "\n".join(lines)


def main():
    merged, branch_authors, tickets_per_email = gather_stats()
    md = build_markdown(merged, branch_authors, tickets_per_email)

    out_path = os.path.join(REPO_DIR, "GIT_STATISTICS.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Statistics written to {out_path}")


if __name__ == "__main__":
    main()

