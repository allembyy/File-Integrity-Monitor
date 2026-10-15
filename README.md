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
- **Windows folder picker** — launch monitoring through `StartMonitor.bat`.

## How It Works

The monitor calculates a SHA-256 hash for each file and compares it with the corresponding hash in the saved baseline.

| Event | Meaning |
|---|---|
| `ADDED` | A file exists but was not recorded in the baseline. |
| `MODIFIED` | A file's current hash differs from its baseline hash. |
| `DELETED` | A file recorded in the baseline is no longer present. |

The baseline is not automatically updated when a change is detected. This preserves the original trusted reference until the user explicitly chooses to rebuild it.

When monitoring starts, the program checks for persistent differences from the baseline before continuing with real-time monitoring.

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
| `monitor.go` | Startup checks and real-time monitoring |
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

The `init` command creates or rebuilds a baseline according to the program's confirmation workflow. The `scan` command performs a one-time comparison, while `monitor` performs startup checks and then watches for real-time changes.

## Testing

Use a disposable test folder to verify the following:

1. Modify an existing file.
2. Add a new file.
3. Delete a file recorded in the baseline.
4. Stop monitoring, modify a file, and restart while keeping the original baseline.
5. Test changes inside nested directories.
6. Verify that events appear in the terminal and are recorded in the audit log.
7. Test keeping an existing baseline versus explicitly rebuilding it.

## Limitations

- Changes made while the monitor is stopped can be detected if their effects still exist when monitoring restarts. The program cannot reconstruct every action that occurred while it was offline.
- Multiple offline edits may appear as one final `MODIFIED` finding.
- The audit log and baseline are not inherently tamper-proof against an attacker with sufficient system permissions.
- Files that cannot be accessed or hashed may not be fully inspected.

## Future Improvements

Potential next steps include:

- Automated Go tests and continuous integration.
- Stronger baseline and audit-log tamper detection.
- Improved rename and directory-deletion handling.
- Configurable exclusions and ignored paths.
- JSON or CSV report export.
- Optional notifications and a graphical dashboard.

## Project Goal

This project explores file integrity verification, baseline-based change detection, filesystem event monitoring, and audit logging as practical applications of cybersecurity and operating-systems concepts.

**Repository:** https://github.com/allembyy/File-Integrity-Monitor
