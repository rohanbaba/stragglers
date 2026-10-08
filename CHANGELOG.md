# Changelog

## 1.0.0

First public release.

- Browser app: pick two drives, see what is missing grouped by folder and by type, choose where each item goes, copy.
- Matching by size and date first, then by content, so moved and renamed files are recognised and most files are never read.
- Repeats inside the source are copied once.
- Folders that look like installed apps or operating system files are flagged and left unticked.
- Copies never overwrite or delete anything, and an interrupted copy leaves no half-written file.
- Reports: `summary.md`, `missing_files.csv`, `copy_log.csv`, `errors.log`.
- Hash cache keyed by drive serial number, so later comparisons are fast even if drive letters change.
- Command-line mode for scripting.
- Works on Windows, macOS and Linux with Python 3.9 or newer. No dependencies.
