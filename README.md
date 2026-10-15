# File Integrity Monitor (FIM)

A Go-based File Integrity Monitor that uses **SHA-256 hashing** to detect file changes against a trusted baseline. It supports startup integrity checks, real-time filesystem monitoring, and audit logging on Windows.

## Features

- **SHA-256 hashing** — creates file fingerprints to verify integrity.
- **Baseline management** — stores a trusted snapshot for each monitored folder.
- **Interactive baseline selection** — keep the existing baseline or confirm creation of a new one.
- **Integrity scanning** — detects added, modified, and deleted files.
- **Startup integrity checks** — identifies persistent changes made while monitoring was stopped.
- **Real-time monitoring** — watches filesystem events using `fsnotify`.
- **Audit logging** — records detected changes in `audit.log`.
- **Colored terminal interface** — makes different event types easier to distinguish.
- **Ransomware-pattern detector** — monitors real-time activity for rapid change bursts, suspicious file extensions, and high Shannon entropy.
- **Windows folder picker** — launch monitoring through `StartMonitor.bat`.

## How It Works

The monitor calculates a SHA-256 hash for each file and compares it with the corresponding hash in the saved baseline.

| Event | Meaning |
|---|---|
| `ADDED` | A file exists but was not recorded in the baseline. |
| `MODIFIED` | A file's current hash differs from its baseline hash. |
| `DELETED` | A file recorded in the baseline is no longer present. |
| `RENAMED` | A file was renamed or replaced during real-time monitoring. |

The baseline is not automatically updated when a change is detected. This preserves the original trusted reference until the user explicitly chooses to rebuild it.

When monitoring starts, the program checks for persistent differences from the baseline before continuing with real-time monitoring.

### Windows Rename Pairing

On Windows, renaming a file produces an `fsnotify.Rename` event for the original name followed immediately by an `fsnotify.Create` event for the destination name. To prevent spurious duplicate `ADDED` notifications:

- **Pairing Window (500 ms):** `RenamePairer` buffers pending rename events for up to 500 ms. When a matching `Create` event arrives, it emits a single `RENAMED <old> -> <new>` event displayed in **cyan** and recorded as `RENAMED <old> -> <new>` in `audit.log`.
- **Baseline Content Verification:** If the original file was tracked in the baseline, the monitor computes the new file's SHA-256 hash and verifies whether the content was preserved (`content unchanged`) or altered (`content modified`). The trusted baseline is never silently rewritten.
- **Unpaired Renames:** If no `Create` event arrives within 500 ms, the event falls back to `DELETED` if the file was tracked in the baseline, or is discarded if untracked.
- **Ransomware Scoring:** Renamed files count as a single event, with suspicious-extension checks (e.g. `.locked`) and entropy analysis evaluated against the new destination path.

## Ransomware-Pattern Detection (Monitor Mode)

During real-time monitoring, incoming filesystem events are processed by an in-memory heuristic detector:

- **Sliding Window:** Evaluates event rates over a sliding time window (default: $N=20$ events within $T=10$ seconds).
- **Suspicious File Extensions:** Detects known ransomware extensions (such as `.locked`, `.encrypted`, `.crypt`, `.crypto`, `.enc`, `.ransom`, `.wnry`, `.clop`).
- **Shannon Entropy Analysis & Compressed-Extension Exclusion:** Computes Shannon entropy on the first 1 MB of added or modified files. Encrypted or random data typically scores $> 7.5$ (on a $0.0 - 8.0$ scale). To eliminate false positives on benign media and archives, files with extensions that are naturally compressed or high entropy (`.zip`, `.7z`, `.rar`, `.gz`, `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.mp3`, `.mp4`, `.mkv`, `.pdf`, `.docx`, `.xlsx`, `.pptx`) are excluded from receiving the entropy bonus.
- **Directory Clustering:** Identifies bursts of modifications or renames concentrated in a single folder.
- **Suspicion Scoring & Threshold:** Combines base event counts with heuristic weights. When the score crosses the threshold, the monitor triggers an alert.
- **Trigger Reason Reporting:** Both the terminal alert banner and `audit.log` entry explicitly state which rule fired (`"event-count rule"`, `"score rule"`, or `"both"`) without displaying contradictory thresholds.
- **Visual Alert Banner:** Displays a bold red terminal alert banner detailing the trigger reason, event count, time window, suspicion score, and sample affected files.
- **Audit Logging:** Appends a structured `RANSOMWARE_SUSPECTED` entry to `audit.log` with the trigger reason, event count, window duration, score, and sample paths.
- **Alert Cooldown:** Applies a configurable cooldown period (default: 30 seconds) after an alert is raised to prevent alert spam during continuous bursts.
- **Strictly Non-Destructive:** The detector is purely observational; it does not delete, move, quarantine, or modify user files.

## Technology Stack

- **Language:** Go
- **Hashing:** SHA-256
- **Filesystem events:** `github.com/fsnotify/fsnotify`
- **Baseline storage:** JSON
- **Platform:** Windows

## Project Structure

| File | Purpose |
|---|---|
| `main.go` | CLI commands, folder validation, and baseline selection |
| `hash.go` | SHA-256 hash calculation |
| `baseline.go` | Baseline creation, loading, saving, and storage |
| `scanner.go` | Integrity comparison and scan report |
| `monitor.go` | Startup checks, real-time monitoring, and detector integration |
| `ransomware.go` | Ransomware detector, sliding window, entropy analysis, and alert logging |
| `ransomware_test.go` | Unit tests for entropy, sliding window, heuristics, and cooldown |
| `simulate_ransomware.ps1` | Safe simulation script restricted to `TestFolder` for demoing alerts |
| `audit.go` | Audit event recording |
| `StartMonitor.bat` | Windows folder picker and launcher |
| `go.mod` / `go.sum` | Go dependencies |

## Getting Started

### Requirements

- Windows
- Go installed
- Git, if cloning the repository

### Clone the repository

```powershell
git clone https://github.com/allembyy/File-Integrity-Monitor.git
cd File-Integrity-Monitor
```

### Build

```powershell
go build -o FileIntegrityMonitor.exe .
```

### Run

Launch `StartMonitor.bat` and select the folder you want to monitor.

You can also use the executable directly:

```powershell
.\FileIntegrityMonitor.exe init "C:\path\to\folder"
.\FileIntegrityMonitor.exe scan "C:\path\to\folder"
.\FileIntegrityMonitor.exe monitor "C:\path\to\folder"
```

The `init` command creates or rebuilds a baseline according to the program's confirmation workflow. The `scan` command performs a one-time comparison, while `monitor` performs startup checks and then watches for real-time changes with active ransomware pattern detection.

## Testing

### Automated Unit Tests

Run the test suite (uses an injected clock and in-memory events with no filesystem dependencies):

```powershell
go test -v ./...
```

The test suite covers:
- Shannon entropy calculations (zeroes, typical text, random bytes)
- Below-threshold event bursts (no alert)
- Above-threshold event bursts (alert triggered)
- Suspicious heuristic triggers (`.locked` extension and high entropy)
- Cooldown suppression and post-cooldown re-alerting

### Interactive Simulation Demo

A dedicated simulation script `simulate_ransomware.ps1` is included to safely demonstrate the ransomware alert. It includes a strict safety guard: **it will only run inside a directory named `TestFolder`**.

To test:

1. In one terminal, start monitoring a disposable folder named `TestFolder`:
   ```powershell
   .\FileIntegrityMonitor.exe monitor ".\TestFolder"
   ```
2. In a second PowerShell window, run the simulation script:
   ```powershell
   .\simulate_ransomware.ps1 -TargetPath ".\TestFolder"
   ```
3. Observe:
   - 50 benign files are created.
   - The files are overwritten with high-entropy cryptographic random bytes.
   - The files are renamed to `.locked`.
   - The monitoring terminal triggers and displays the red **CRITICAL SECURITY ALERT: RANSOMWARE** banner.
   - `audit.log` records the `RANSOMWARE_SUSPECTED` event with sample paths.

## Limitations

- **Heuristic Detection Limitations:** Ransomware detection is based on heuristics (rapid bursts, suspicious extensions, high Shannon entropy). Legitimate intensive file operations (such as compiling software, extracting large archives, or disk encryption utilities) may generate similar patterns and cause false positives. Conversely, low-and-slow ransomware attacks intentionally designed to modify files below rate thresholds may avoid triggering the sliding window. Heuristic detection serves as an early-warning indicator and is not an absolute security guarantee.
- **Compressed & Media Extension Exclusion:** To avoid false positives on legitimate archives and office documents, files matching `CompressedOrHighEntropyExtensions` (`.zip`, `.docx`, `.pdf`, `.jpg`, etc.) do not receive the entropy bonus. Consequently, ransomware that encrypts such files in-place without changing their extension will rely primarily on event-rate and directory-clustering rules rather than entropy.
- **Rename Pairing Window Limitations:** File renames separated by more than the 500 ms pairing window (e.g. cross-volume transfers or prolonged storage system delays) will not be paired and will appear as separate deletion and addition events. Unpaired renames on files not tracked in the baseline are ignored to prevent phantom delete alerts on short-lived temporary files.
- **Offline Modifications:** Changes made while the monitor is stopped can be detected upon restart if their effects still exist. However, the program cannot reconstruct every individual intermediate step taken offline.
- **Multiple Offline Edits:** Multiple offline edits appear as a single final `MODIFIED` finding.
- **Tamper Resistance:** The audit log and local baseline are not inherently tamper-proof against an attacker with administrative system permissions.
- **Access Restrictions:** Files that cannot be accessed due to file locks or permissions may not be inspected.

## Future Improvements

Potential next steps include:

- Automated continuous integration workflows.
- Stronger baseline and audit-log tamper detection (e.g. append-only signatures).
- Configurable exclusions, white-listed extensions, and ignored paths.
- JSON or CSV report export.
- Automated quarantine or notification popups.

## Project Goal

This project explores file integrity verification, baseline-based change detection, filesystem event monitoring, and audit logging as practical applications of cybersecurity and operating-systems concepts.

**Repository:** https://github.com/allembyy/File-Integrity-Monitor
