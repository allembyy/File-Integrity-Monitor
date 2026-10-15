# File Integrity Monitor (FIM)

A lightweight, command-line File Integrity Monitor built with **Go** for Windows. It uses SHA-256 cryptographic hashing to establish a trusted baseline of files and detect unauthorized or unexpected changes.

## Overview

File integrity monitoring helps identify changes to files that may indicate accidental modification, corruption, or potentially malicious activity.

This project recursively scans a target directory, calculates SHA-256 hashes for its files, and stores them in a JSON baseline. Subsequent scans compare the current state against that baseline and report modified, added, and deleted files.

## Features

- **SHA-256 Hashing:** Generates cryptographic hashes using Go's `crypto/sha256` package.
- **Recursive Scanning:** Traverses subdirectories to monitor files.
- **Baseline Creation:** Records file paths and hashes in a JSON file.
- **Integrity Verification:** Compares current file hashes against the saved baseline.
- **Change Detection:** Identifies modified, added, and deleted files.
- **Command-Line Interface:** Supports baseline initialization and integrity scans.

## Tech Stack

- **Language:** Go
- **Cryptography:** SHA-256
- **Data Storage:** JSON
- **Platform:** Windows
- **Version Control:** Git and GitHub

## Getting Started

### Prerequisites

- Windows
- [Go](https://go.dev/dl/) installed and available in your PATH
- Git (optional, for cloning the repository)

### Installation

Clone the repository:

```bash
git clone https://github.com/allembyy/File-Integrity-Monitor.git
cd File-Integrity-Monitor
```

### Usage

**1. Create a baseline**

Run the following command from the project root:

```powershell
go run -buildvcs=false . init ".\TestFolder"
```

Replace `.\TestFolder` with the directory you want to monitor.

This recursively hashes the files in the target directory and saves the baseline to `baseline.json` in the project root.

**2. Scan for changes**

```powershell
go run -buildvcs=false . scan ".\TestFolder"
```

The scan compares the current directory contents against the saved baseline.

### Example Output

```text
--- Integrity Report ---
[MODIFIED]  C:\...\TestFolder\test.txt
[ADDED]     C:\...\TestFolder\newfile.txt
[DELETED]   C:\...\TestFolder\oldfile.txt

Summary: 1 modified, 1 added, 1 deleted
```

The output above is an example; actual results depend on the files in the monitored directory.

## How It Works

1. **Initialization:** Recursively scans the target directory and calculates a SHA-256 hash for each file.
2. **Baseline Storage:** Saves file paths and their hashes in `baseline.json`.
3. **Integrity Scan:** Recalculates hashes and compares them with the baseline.
4. **Change Reporting:** Reports files as modified, added, or deleted.

The baseline is not automatically updated during a scan, allowing changes to remain detectable until you intentionally create a new baseline.

## Project Structure

```text
File-Integrity-Monitor/
├── main.go
├── go.mod
├── .gitignore
└── baseline.json    # Generated locally; not committed
```

## Current Limitations

- Currently supports manual scans through the command line.
- File monitoring depends on the integrity of the saved baseline.
- Does not yet provide real-time monitoring or automated alerts.
- Intended as an educational project, not a replacement for enterprise security software.

## Planned Improvements

- Real-time Windows filesystem monitoring using `ReadDirectoryChangesW`.
- Improved event handling and change reporting.
- Logging and configurable monitoring options.
- Stronger baseline protection and integrity verification.
- Unit tests and improved error handling.

## Learning Objectives

This project explores practical applications of:

- Operating system file handling and directory traversal.
- Cryptographic hashing and file integrity verification.
- Command-line application development in Go.
- Filesystem monitoring and security concepts.

## Disclaimer

This project is developed for educational purposes to explore file integrity monitoring and operating system security concepts.

## License

No license has been added yet. Add a license if you intend to permit others to use, modify, or distribute this project.
