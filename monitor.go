package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ANSI colors for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// printBanner displays the monitoring header.
func printBanner(folder string) {
	fmt.Println()
	fmt.Println(colorCyan + colorBold +
		"╔══════════════════════════════════════════════════════╗")
	fmt.Println(
		"║              FILE INTEGRITY MONITOR                  ║")
	fmt.Println(
		"║                   REAL-TIME MODE                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝" +
		colorReset)

	fmt.Println()
	fmt.Println(colorGreen + "  [✓] Status    : MONITORING" + colorReset)
	fmt.Println(colorWhite + "  [i] Directory : " + folder + colorReset)
	fmt.Println(colorWhite + "  [i] Started   : " +
		time.Now().Format("2006-01-02 15:04:05") + colorReset)
	fmt.Println()
	fmt.Println(colorCyan +
		"──────────────────── EVENT LOG ────────────────────────" +
		colorReset)
	fmt.Println()
}

// printEvent displays a colored file-change event.
func printEvent(event, path string) {
	color := colorWhite
	symbol := "*"

	switch event {
	case "ADDED":
		color = colorGreen
		symbol = "+"
	case "MODIFIED":
		color = colorYellow
		symbol = "~"
	case "DELETED":
		color = colorRed
		symbol = "!"
	}

	fmt.Printf("%s%s  [%s] %-8s %s%s\n",
		color,
		time.Now().Format("15:04:05"),
		symbol,
		event,
		path,
		colorReset,
	)
}

// addDirectories registers a folder and all its subdirectories.
func addDirectories(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return watcher.Add(path)
		}

		return nil
	})
}

// compareWithBaseline finds files added, modified, or deleted
// since the trusted baseline was created.
func compareWithBaseline(
	folder string,
	known Baseline,
) ([]Change, error) {
	current, err := createBaseline(folder)
	if err != nil {
		return nil, err
	}

	var changes []Change

	for path, currentHash := range current {
		oldHash, exists := known[path]

		if !exists {
			changes = append(changes, Change{
				Event: "ADDED",
				Path:  path,
			})
		} else if oldHash != currentHash {
			changes = append(changes, Change{
				Event: "MODIFIED",
				Path:  path,
			})
		}
	}

	for path := range known {
		if _, exists := current[path]; !exists {
			changes = append(changes, Change{
				Event: "DELETED",
				Path:  path,
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			return changes[i].Event < changes[j].Event
		}
		return changes[i].Path < changes[j].Path
	})

	return changes, nil
}

// monitorFolder checks for changes missed while stopped, then
// watches for new filesystem events in real time.
func monitorFolder(folder, baselinePath, logPath string) error {
	known, err := loadBaseline(baselinePath)
	if err != nil {
		return fmt.Errorf("cannot load baseline: %w", err)
	}

	// Start watching before the initial comparison so changes
	// during the scan can also generate filesystem events.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create watcher: %w", err)
	}
	defer watcher.Close()

	if err := addDirectories(watcher, folder); err != nil {
		return fmt.Errorf("cannot watch folder: %w", err)
	}

	// Compare current files with the original baseline.
	startupChanges, err := compareWithBaseline(folder, known)
	if err != nil {
		return fmt.Errorf("startup integrity scan failed: %w", err)
	}

	printBanner(folder)

	if len(startupChanges) == 0 {
		fmt.Println(colorGreen +
			"  [✓] Startup scan: No changes detected." +
			colorReset)
	} else {
		fmt.Println(colorYellow +
			"  [!] Startup scan: Changes detected since baseline." +
			colorReset)
		fmt.Println()

		if err := appendAuditLog(
			logPath,
			folder,
			startupChanges,
		); err != nil {
			return fmt.Errorf("cannot write startup changes to audit log: %w", err)
		}

		for _, change := range startupChanges {
			relativePath, relErr := filepath.Rel(folder, change.Path)
			if relErr != nil {
				relativePath = change.Path
			}
			printEvent(change.Event, relativePath)
		}

		fmt.Println(colorGreen +
			"          Startup changes written to audit log" +
			colorReset)
	}

	fmt.Println()
	fmt.Println(colorWhite +
		"  Press Ctrl+C to stop monitoring." +
		colorReset)
	fmt.Println()

	// Track events already reported during this monitoring session.
	reported := make(map[string]string)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			path, err := filepath.Abs(event.Name)
			if err != nil {
				fmt.Println(colorRed +
					"Cannot resolve event path: " + err.Error() +
					colorReset)
				continue
			}
			path = filepath.Clean(path)

			// Start watching newly created directories.
			if event.Op&fsnotify.Create != 0 {
				info, statErr := os.Stat(path)
				if statErr == nil && info.IsDir() {
					if err := addDirectories(watcher, path); err != nil {
						fmt.Println(colorYellow +
							"Warning: cannot watch new directory: " +
							err.Error() + colorReset)
					}
					continue
				}
			}

			relevant := event.Op & (fsnotify.Create |
				fsnotify.Write |
				fsnotify.Remove |
				fsnotify.Rename)

			if relevant == 0 {
				continue
			}

			// Give file writes a short time to settle.
			time.Sleep(200 * time.Millisecond)

			info, statErr := os.Stat(path)

			var change Change
			var signature string

			if statErr != nil {
				if !os.IsNotExist(statErr) {
					fmt.Println(colorRed +
						"Cannot inspect file: " + path + ": " +
						statErr.Error() + colorReset)
					continue
				}

				if _, exists := known[path]; !exists {
					continue
				}

				change = Change{
					Event: "DELETED",
					Path:  path,
				}
				signature = "DELETED"
			} else {
				if info.IsDir() {
					continue
				}

				hash, hashErr := calculateHash(path)
				if hashErr != nil {
					fmt.Println(colorYellow +
						"File is temporarily unavailable: " + path +
						colorReset)
					continue
				}

				oldHash, exists := known[path]

				if !exists {
					change = Change{
						Event: "ADDED",
						Path:  path,
					}
					signature = "ADDED"
				} else if oldHash != hash {
					change = Change{
						Event: "MODIFIED",
						Path:  path,
					}
					signature = "MODIFIED:" + hash
				} else {
					// File matches the original baseline again.
					delete(reported, path)
					continue
				}
			}

			if reported[path] == signature {
				continue
			}

			if err := appendAuditLog(
				logPath,
				folder,
				[]Change{change},
			); err != nil {
				fmt.Println(colorRed +
					"Audit log error: " + err.Error() +
					colorReset)
				continue
			}

			reported[path] = signature

			relativePath, err := filepath.Rel(folder, path)
			if err != nil {
				relativePath = path
			}

			printEvent(change.Event, relativePath)
			fmt.Println(colorGreen +
				"          Audit log updated" +
				colorReset)
			fmt.Println()

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Println(colorRed +
				"Watcher error: " + err.Error() +
				colorReset)
		}
	}
}
