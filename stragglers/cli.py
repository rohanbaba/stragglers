"""Command line entry point. With no source and destination it opens the
browser app; with both it runs in the terminal."""

import argparse
import json
import os
import shutil
import sys
import threading
from collections import Counter

from . import __version__
from .engine import (CopyJob, ScanJob, clean_dest, default_data_dir, fmt_dur, human,
                     safe_name)


def ask(prompt, valid):
    valid = [v.lower() for v in valid]
    while True:
        try:
            ans = input(prompt).strip().lower()
        except EOFError:
            return "q"
        if ans in valid:
            return ans
        print("  Please enter one of: " + ", ".join(valid))


def progress_printer(progress, stop):
    width = max(40, shutil.get_terminal_size((100, 20)).columns - 1)
    last = None
    while not stop.is_set():
        s = progress.snap()
        if last is not None and s["step"] != last:
            sys.stdout.write("\n")
        last = s["step"]
        line = f"  {s['steps'][s['step']]}: "
        if s["total"]:
            line += f"{s['done']:,}/{s['total']:,} files"
        elif s["done"]:
            line += f"{s['done']:,} files"
        if s["bytes"]:
            line += f", {human(s['bytes'])}"
            if s["bytes_total"]:
                line += f" of {human(s['bytes_total'])}"
        if s["eta"] and s["step_elapsed"] > 5:
            line += f", about {fmt_dur(s['eta'])} left"
        sys.stdout.write("\r" + line[:width].ljust(width))
        sys.stdout.flush()
        stop.wait(0.5)
    sys.stdout.write("\n")


def with_printer(progress, fn):
    stop = threading.Event()
    th = threading.Thread(target=progress_printer, args=(progress, stop), daemon=True)
    th.start()
    try:
        return fn()
    finally:
        stop.set()
        th.join()


def print_summary(plan, run_dir):
    t, blocks = Counter(plan["totals"]), plan["blocks"]

    def row(title, k):
        print(f"  {title:<40}{t[k + '_n']:>12,} files  {human(t[k + '_b']):>10}")

    print("\n" + "-" * 72)
    print(f"  {plan['source_root']}  ->  {plan['target_root']}   ({fmt_dur(plan['elapsed'])})")
    print("-" * 72)
    row("Scanned on the source", "total")
    row("Already there, same folder", "same")
    row("Already there, another folder", "moved")
    row("Missing", "missing")
    if t["dup_n"]:
        row("Repeats of missing files", "dup")
    if t["error_n"]:
        row("Could not be read", "error")
    if blocks:
        print("\n  Missing, by type (repeats removed):")
        for cat, c in sorted(plan["categories"].items(), key=lambda kv: -kv[1]["unique_bytes"]):
            print(f"    {cat:<16}{c['items']:>7,} items {human(c['unique_bytes']):>12}")
    print(f"\n  Report: {os.path.join(run_dir, 'summary.md')}")


def choose_cli(plan, include_system):
    blocks = [b for b in plan["blocks"] if include_system or not b["system"]]
    archive = f"From {safe_name(plan['source_label'])}"

    def archive_dest(b):
        return os.path.join(archive, b["src"]) if b["src"] else archive

    hidden = len(plan["blocks"]) - len(blocks)
    print("\nWhat would you like to do?")
    if hidden:
        print(f"  ({hidden:,} items that look like apps or system files are left out. "
              f"Use --include-system to include them.)")
    print("  [r] Review each item")
    print("  [c] Copy everything to the suggested places")
    print(f"  [a] Copy everything into a new folder: {archive}")
    print("  [q] Quit")
    mode = ask("Choice [r/c/a/q]: ", ["r", "c", "a", "q"])
    if mode == "q":
        return []
    if mode in ("c", "a"):
        return [(b, b["suggested_dest"] if mode == "c" else archive_dest(b)) for b in blocks]
    decisions = []
    for n, b in enumerate(blocks, 1):
        kind = "Whole folder" if b["kind"] == "folder" else "Files in"
        print(f"\n[{n}/{len(blocks)}] {kind} {b['src'] or '(top level)'}  "
              f"({b['category']}, {b['count']:,} files, {human(b['bytes'])})")
        print(f"  1) Suggested place: {b['suggested_dest'] or '(top level)'}   ({b['reason']})")
        print(f"  2) New folder:      {archive_dest(b)}")
        print("  3) Skip   4) Type a place   q) Stop reviewing")
        ans = ask("  Choice: ", ["1", "2", "3", "4", "q"])
        if ans == "q":
            break
        if ans == "1":
            decisions.append((b, b["suggested_dest"]))
        elif ans == "2":
            decisions.append((b, archive_dest(b)))
        elif ans == "4":
            while True:
                try:
                    decisions.append((b, clean_dest(input("  Folder: "), plan["target_root"])))
                    break
                except ValueError as e:
                    print(f"  {e}")
    return decisions


def run_cli(args, data_dir):
    if args.copy_plan:
        with open(args.copy_plan, "r", encoding="utf-8") as f:
            plan = json.load(f)
        run_dir = os.path.dirname(os.path.abspath(args.copy_plan))
    else:
        job = ScanJob(args.source, args.target, args.label, data_dir,
                      thorough=args.thorough, include_hidden=args.include_hidden)
        try:
            job.validate()
        except ValueError as e:
            sys.exit(str(e))
        print(f"\n  From: {job.src}\n  To:   {job.tgt}\n")
        plan = with_printer(job.progress, job.run)
        run_dir = job.run_dir
        print_summary(plan, run_dir)
        if args.report_only or not plan["blocks"]:
            return
    decisions = choose_cli(plan, args.include_system)
    if not decisions:
        return
    cj = CopyJob(plan, decisions, run_dir, verify=args.verify)
    jobs, skipped = cj.jobs()
    total = sum(s for _, s, _ in jobs)
    print(f"\nReady to copy {len(jobs):,} files ({human(total)}), skipping {len(skipped):,} repeats. "
          f"Free space: {human(shutil.disk_usage(plan['target_root']).free)}.")
    if ask("Start copying? [y/n]: ", ["y", "n"]) != "y":
        return
    counts = with_printer(cj.progress, cj.run)
    print(f"\n  Copied: {counts['copied']:,}   Already there: {counts['already there']:,}   "
          f"Repeats skipped: {counts['repeat skipped']:,}   Failed: {counts['failed']:,}")
    if cj.stopped_reason:
        print(f"  {cj.stopped_reason}")
    print(f"  Copy log: {cj.log_path}")


def main(argv=None):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        prog="stragglers",
        description="Find the files on one drive that another drive is missing, even when "
                    "they were moved or renamed, and copy them over. With no --source and "
                    "--target it opens in your browser.")
    ap.add_argument("-s", "--source", help="drive or folder that may have extra files")
    ap.add_argument("-t", "--target", help="drive or folder to copy into (your main backup)")
    ap.add_argument("--label", help="short name for the source, used in file names")
    ap.add_argument("--report-only", action="store_true", help="scan and write the report, copy nothing")
    ap.add_argument("--copy-plan", metavar="PLAN_JSON", help="copy using plan.json from an earlier scan")
    ap.add_argument("--thorough", action="store_true",
                    help="also find small files that were both renamed and re-dated (slow)")
    ap.add_argument("--verify", action="store_true", help="re-read every copied file to confirm it")
    ap.add_argument("--include-system", action="store_true",
                    help="terminal mode: also offer items that look like apps or system files")
    ap.add_argument("--include-hidden", action="store_true",
                    help="also scan Recycle Bin, Thumbs.db, .DS_Store and similar")
    ap.add_argument("--data-dir", help=f"where scans and the hash cache are kept (default: {default_data_dir()})")
    ap.add_argument("--port", type=int, default=8765, help="port for the browser app")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    ap.add_argument("--version", action="version", version=f"stragglers {__version__}")
    args = ap.parse_args(argv)
    data_dir = args.data_dir or default_data_dir()
    try:
        if args.copy_plan or (args.source and args.target):
            run_cli(args, data_dir)
        elif args.source or args.target:
            ap.error("give both --source and --target, or neither to open the browser app")
        else:
            from .app import serve
            serve(data_dir, port=args.port, open_browser=not args.no_browser)
    except KeyboardInterrupt:
        print("\n  Stopped. A file that was mid-copy has been removed; finished files are safe.")
